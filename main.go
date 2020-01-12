package main

import (
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strings"
)

type ResourceAccess struct {
	SampleExternalPartner struct {
		Roles []string `json:"roles"`
	} `json:"sample-client"`
}

type CustomClaims struct {
	ClientId string `json:"clientId"`
	Email string `json:"email"`
	ResourceAccess ResourceAccess `json:"resource_access"`
	jwt.StandardClaims
}

const BearerSchema string = "Bearer "
var RequiredRoles []string = []string{"sample-client-role", "any_role"}

func PluginMain(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		logger(w.Write([]byte("Authorization header required")))
		return
	}
	if !strings.HasPrefix(authHeader, BearerSchema) {
		w.WriteHeader(http.StatusUnauthorized)
		logger(w.Write([]byte("Authorization requires Bearer scheme")))
		return
	}

	reqToken := authHeader[len(BearerSchema):]

	token, _, err := new(jwt.Parser).ParseUnverified(reqToken, &CustomClaims{})

	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(*CustomClaims); ok {
		if contains(claims.ResourceAccess.SampleExternalPartner.Roles, RequiredRoles){
			w.Header().Set("ClientId", claims.ClientId)
			w.Header().Set("Roles", strings.Join(claims.ResourceAccess.SampleExternalPartner.Roles, ","))
			w.WriteHeader(http.StatusOK)
		}else{
			w.WriteHeader(http.StatusUnauthorized)
			logger(w.Write([]byte("Has no required role")))
		}
		return
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		logger(w.Write([]byte("Has no required claims")))
		return
	}
}

func contains(a []string, b []string) bool {
	m := make(map[string]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			return true
		}
	}
	return false
}

func logger(n int, err error) {
	if err != nil {
		log.Printf("Write failed: %v", err)
	}
}
//Below is to run this project standalone for test/debugging
//func main() {
//	http.HandleFunc("/plugin", PluginMain)
//	log.Fatal(http.ListenAndServe(":8091", nil))
//}
