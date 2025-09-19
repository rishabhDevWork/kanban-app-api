package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"github.com/xeipuuv/gojsonschema"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Project struct {
	ProjectID       string   `json:"projectid,omitempty"`
	UserID          string   `json:"userid,omitempty"`
	Name            string   `json:"name,omitempty"`
	RepoURL         string   `json:"repo_url,omitempty"`
	SiteURL         string   `json:"site_url,omitempty"`
	Description     string   `json:"description,omitempty"`
	Dependencies    []string `json:"dependencies,omitempty"`
	DevDependencies []string `json:"dev_dependencies,omitempty"`
	Status          string   `json:"status,omitempty"`
}

type Claim struct {
	Username string `json:"username"`
	UserId   string `json:"userid"`
	jwt.RegisteredClaims
}

type UserRepsonse struct {
	UserId   string `json:"userid"`
	UserName string `json:"username"`
	Token    string `json:"token"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type response struct {
	Message string `json:"message"`
	Id      string `json:"id,omitempty"`
}

func (app *App) generateToken(username string, userId string) (string, error) {
	expirationTime := time.Now().Add(time.Hour * 3)

	claims := &Claim{
		Username: username,
		UserId:   userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("err loading env variables")
	}

	var loadErr error
	userSchema, loadErr := loadSchema("schemas/user.json")
	if loadErr != nil {
		log.Fatalf("Error loading schema: %v", loadErr)
	}

	projectSchema, loadErr := loadSchema("schemas/project.json")
	if loadErr != nil {
		log.Fatalf("Error loading schema: %v", loadErr)
	}

	Turso_Token := os.Getenv("TURSO_AUTH_TOKEN")
	Turso_Url := os.Getenv("TURSO_DATABASE_URL")

	dsn := Turso_Url + "?authToken=" + Turso_Token

	DB, err := sql.Open("libsql", dsn)
	if err != nil {
		log.Fatal("Error connecting to DB")
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal("error pinging DB")
	}

	defer DB.Close()

	app := &App{
		DB:     DB,
		JWTKey: []byte(os.Getenv("JWT_TOKEN_SECRET")),
	}

	router := mux.NewRouter()
	routes(router, app, userSchema, projectSchema)

	log.Println("Server started at port :8080....")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func routes(router *mux.Router, app *App, userSchema, projectSchema string) {
	//Middleware for User
	userChain := alice.New(logginMiddleware, validateMiddleware(userSchema))
	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("POST")

	//Middleware for api without request body
	projectChain := alice.New(logginMiddleware, app.jwtMiddleware)
	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
	router.Handle("/projects/{project_id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
	router.Handle("/projects/{project_id}", projectChain.ThenFunc(app.deleteProject)).Methods("DELETE")

	//Middleware for ProjectAPIs with request body
	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.createProject)).Methods("POST")
	router.Handle("/projects/{project_id}", projectChainWithValidation.ThenFunc(app.updateProject)).Methods("PUT")
}

func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func logginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			responseWithError(w, http.StatusUnauthorized, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claim{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				responseWithError(w, http.StatusUnauthorized, "Invalid token signature")
				return
			}
			responseWithError(w, http.StatusBadRequest, "Invalid Token")
			return
		}

		if !token.Valid {
			responseWithError(w, http.StatusBadRequest, "Invalid Token")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				responseWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}
			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				responseWithError(w, http.StatusBadRequest, "Invalid JSON body")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)

			documentLoader := gojsonschema.NewGoLoader(body)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				responseWithError(w, http.StatusInternalServerError, "Error validating JSON")
				return
			}
			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				responseWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}

func responseWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

// register function to handle user registration
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	creds := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	stmt := `INSERT INTO users (username, password) VALUES (?,?)`
	result, err := app.DB.Exec(stmt, creds.Username, string(hashedPassword))
	if err != nil {
		responseWithError(w, 500, "Error running user register query")
		return
	}

	userId, err := result.LastInsertId()
	if err != nil {
		responseWithError(w, 500, "Error running user register query")
		return
	}

	userToken, err := app.generateToken(creds.Username, strconv.Itoa(int(userId)))
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error generating user token")
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(UserRepsonse{UserName: creds.Username, UserId: strconv.Itoa(int(userId)), Token: userToken})
}

// login
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	creds := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	stmt := `Select id, username, password from users where username = ?`

	var storedCreds Credentials
	var userId string

	row := app.DB.QueryRow(stmt, creds.Username)
	err = row.Scan(&userId, &storedCreds.Username, &storedCreds.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusUnauthorized, "Invalid Username or Password")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "Error getting stored data")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			responseWithError(w, http.StatusUnauthorized, "Incorrect Password")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "Error verifing password")
		return
	}

	userToken, err := app.generateToken(creds.Username, userId)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error generating user token")
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(UserRepsonse{UserName: creds.Username, UserId: userId, Token: userToken})
}

// createProject
func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	claims := r.Context().Value("claims").(*Claim)
	userId := claims.UserId

	dependenciesJSON, err := json.Marshal(project.Dependencies)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	devDependenciesJSON, err := json.Marshal(project.DevDependencies)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	stmt := `INSERT INTO projects (name, repo_url, site_url, description, dependencies, dev_dependencies, status, user_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	row, err := app.DB.Exec(stmt, project.Name, project.RepoURL, project.SiteURL, project.Description, string(dependenciesJSON), string(devDependenciesJSON), project.Status, userId)
	if err != nil {
		responseWithError(w, 500, "Error running user create project query")
		return
	}
	projectId, err := row.LastInsertId()
	if err != nil {
		responseWithError(w, 500, "Error running user create project query")
		return
	}

	project.ProjectID = strconv.FormatInt(projectId, 10)

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(project)
}

// updateProject
func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	vars := mux.Vars(r)
	projectId := vars["project_id"]

	claims := r.Context().Value("claims").(*Claim)
	userId := claims.UserId
	var storedUserId string

	stmt := `select user_id from projects where id = ?`
	row := app.DB.QueryRow(stmt, projectId)

	err = row.Scan(&storedUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusNotFound, "Project Not Found")
			return
		}
		responseWithError(w, 500, "Error fetching projects")
		return
	}

	if storedUserId != userId {
		responseWithError(w, http.StatusForbidden, "You do not have permission to update this project")
		return
	}
	dependenciesJSON, err := json.Marshal(project.Dependencies)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	devDependenciesJSON, err := json.Marshal(project.DevDependencies)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	stmt = `UPDATE projects SET name=?, repo_url=?, site_url=?, description=?, dependencies=?, dev_dependencies=?, status=? WHERE id=? AND user_id=?`
	result, err := app.DB.Exec(stmt, project.Name, project.RepoURL, project.SiteURL, project.Description, string(dependenciesJSON), string(devDependenciesJSON), project.Status, projectId, userId)
	log.Println(result)
	if err != nil {
		log.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error running update project query")
		return
	}

	project.ProjectID = projectId
	project.UserID = userId

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// getProjects
func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claim)
	userId := claims.UserId

	stmt := `select id, name, repo_url, site_url, description, dependencies, dev_dependencies, status, user_id from projects where user_id = ?`
	rows, err := app.DB.Query(stmt, userId)
	if err != nil {
		responseWithError(w, 500, "Error getting projects")
		return
	}

	projects := []Project{}
	for rows.Next() {
		var depsJSON, devDepsJSON string

		project := Project{}
		err := rows.Scan(&project.ProjectID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, &depsJSON, &devDepsJSON, &project.Status,
			&project.UserID)
		if err != nil {
			responseWithError(w, 500, "Error scanning projects")
			return
		}
		json.Unmarshal([]byte(depsJSON), &project.Dependencies)
		json.Unmarshal([]byte(devDepsJSON), &project.DevDependencies)
		projects = append(projects, project)
	}
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(projects)
}

// getProject
func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectId := vars["project_id"]

	claims := r.Context().Value("claims").(*Claim)
	userId := claims.UserId
	project := Project{}
	var depsJSON, devDepsJSON string

	stmt := `select id, name, repo_url, site_url, description, dependencies, dev_dependencies, status, user_id from projects where id =? AND user_id =?`
	row := app.DB.QueryRow(stmt, projectId, userId)

	err := row.Scan(&project.ProjectID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, &depsJSON, &devDepsJSON, &project.Status,
		&project.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusNotFound, "Project Not Found")
			return
		}
		responseWithError(w, 500, "Error fetching projects")
		return
	}
	json.Unmarshal([]byte(depsJSON), &project.Dependencies)
	json.Unmarshal([]byte(devDepsJSON), &project.DevDependencies)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// deleteProject
func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectId := vars["project_id"]

	claims := r.Context().Value("claims").(*Claim)
	userId := claims.UserId

	var storedUserId string
	stmt := `select user_id from projects where id=?`

	row := app.DB.QueryRow(stmt, projectId)
	err := row.Scan(&storedUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusNotFound, "Project Not Found")
			return
		}
		responseWithError(w, 500, "Error fetching projects")
		return
	}

	if storedUserId != userId {
		responseWithError(w, http.StatusForbidden, "You do not have permission to delete this project")
		return
	}

	stmt = `DELETE from projects where id=? AND user_id=?`
	_, err = app.DB.Exec(stmt, projectId, userId)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error deleting the project")
	}

	w.WriteHeader(http.StatusNoContent)
}
