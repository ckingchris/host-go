package main

import (
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"html/template"
        "net/http"
        "time"
        "log"
)

type user struct {
        Username string
        Password []byte
        Fname    string
        Lname    string
        Role     string
}

type session struct {
	un           string
	lastActivity time.Time
}

type meta struct {
        Title   string
        Content string
}

type ErrorMessage struct {
        Error string
}

var tpl *template.Template
var dbUsers = map[string]user{}       // user ID, user
var dbSessions = map[string]session{} // session ID, session

var dbSessionsCleaned time.Time // remove later

const sessionLength int = 3000

func init() {
        tpl = template.Must(template.ParseGlob("templates/*"))
        dbSessionsCleaned = time.Now()
}

func main() {
        http.HandleFunc("/favicon.ico", faviconHandler)
        http.HandleFunc("/", indexHandler)
        http.HandleFunc("/admin", adminHandler)
        http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
        http.HandleFunc("/logout", authorized(logoutHandler))
        http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("./public"))))
	http.ListenAndServe(":8080", nil)
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "favicon.ico")
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
        u := getUser(w, req)
        m := meta{
                Title: "Chris King | Full Stack Web Developer",
                Content: "Full Stack Web Developer, currently based in Las Vegas, Nevada",
        }
        showSessions() 
        err := tpl.ExecuteTemplate(w, "index.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}})
        if err != nil {
		log.Fatalln(err)
	}
}

func adminHandler(w http.ResponseWriter, req *http.Request) {
        u := getUser(w, req)
        m := meta{
                Title: "Chris King | Admin",
                Content: "Admin",
        }
	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
	if u.Role != "admin" {
		http.Error(w, "You must be an admin to enter", http.StatusForbidden)
		return
	}
	showSessions() // for demonstration purposes
        err := tpl.ExecuteTemplate(w, "admin.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}})
        if err != nil {
		log.Fatalln(err)
	}
}

func signupHandler(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
        var u user
        m := meta{
                Title: "Chris King | Sign up",
                Content: "Signup",
        }
        e := ErrorMessage{
                Error: "Username already exists",
        }
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		un := req.FormValue("username")
		p := req.FormValue("password")
		f := req.FormValue("fname")
		l := req.FormValue("lname")
		r := req.FormValue("role")
		// check if username exists
		if _, ok := dbUsers[un]; ok {
                        tpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}, "Error":[]ErrorMessage{e}})
			// http.Error(w, "Username already exists", http.StatusForbidden)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		c.MaxAge = sessionLength
		http.SetCookie(w, c)
		dbSessions[c.Value] = session{un, time.Now()}
		// store user in dbUsers
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		u = user{un, bs, f, l, r}
		dbUsers[un] = u
		// redirect
		http.Redirect(w, req, "/admin", http.StatusSeeOther)
		return
        }
	showSessions() // for demonstration purposes
	tpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}})
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
        var u user
        m := meta{
                Title: "Chris King | Login",
                Content: "Login",
        }
        e := ErrorMessage{
                Error: "Username and/or password do not match",
        }
	// process form submission
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		// is there a username?
                u, ok := dbUsers[un]
		if !ok {
                        tpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}, "Error":[]ErrorMessage{e}})
			// http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// does the entered password match the stored password?
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
                        tpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}, "Error":[]ErrorMessage{e}})
			// http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		c.MaxAge = sessionLength
		http.SetCookie(w, c)
		dbSessions[c.Value] = session{un, time.Now()}
		http.Redirect(w, req, "/admin", http.StatusSeeOther)
		return
        }
	showSessions() // for demonstration purposes
	tpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"User":[]user{u}, "Meta":[]meta{m}})
}

func logoutHandler(w http.ResponseWriter, req *http.Request) {
	c, _ := req.Cookie("session")
	// delete the session
	delete(dbSessions, c.Value)
	// remove the cookie
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
        http.SetCookie(w, c)
        
        // clean up dbSessions
	if time.Now().Sub(dbSessionsCleaned) > (time.Second * 30) {
		go cleanSessions()
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func authorized(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// code before
		if !alreadyLoggedIn(w, r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h.ServeHTTP(w, r)
		// code after
	})
}
