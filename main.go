package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtAccessTokenSecret  = "keyboard cat"
	jwtRefreshTokenSecret = "keyboard dog"
	jwtAccessTokenExpire  = 2
	jwtRefreshTokenExpire = 168
)

type JwtCustomRefreshClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

type JwtCustomClaims struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	jwt.RegisteredClaims
}

type User struct {
	ID       primitive.ObjectID `bson:"id"`
	Name     string             `bson:"name"`
	Email    string             `bson:"email"`
	Password string             `bson:"password"`
}

type SignUpRequest struct {
	Name     string `json:"name" form:"name" binding:"required`
	Email    string `json:"email" form:"email" binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type SignupResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func main() {
	app := gin.Default()

	router := app.Group("/")
	router.POST("/signup", signupHandler)
	router.POST("/signin", signinHandler)

	authRouter := router.Group("/").Use(jwtAuthMiddleware())
	{
		authRouter.GET("/profile", profileHandler)
	}

	app.Run(":7002")
}

func jwtAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		headerAuthorization := ctx.Request.Header.Get("Authorization")
		authorization := strings.Split(headerAuthorization, " ")
		if len(authorization) == 2 {
			token := authorization[1]
			authorized, err := isAuthorized(token, jwtAccessTokenSecret)
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"msg": "Not authorized",
				})
				return
			}

			if authorized {
				userID, err := extractIDFromToken(token, jwtAccessTokenSecret)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"msg": "Not authorized",
					})
					return
				}

				ctx.Set("x-user-id", userID)
				ctx.Next()
				return
			}

			return
		}

		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"msg": "Not authorized",
		})
	}
}

func signupHandler(ctx *gin.Context) {
	var signup SignUpRequest

	if err := ctx.ShouldBind(&signup); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"msg": "Bad request",
		})
		return
	}

	// check exists email

	// generate password
	password, err := bcrypt.GenerateFromPassword([]byte(signup.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
		return
	}

	signup.Password = string(password)
	user := User{
		ID:       primitive.NewObjectID(),
		Name:     signup.Name,
		Email:    signup.Email,
		Password: signup.Password,
	}

	// TODO: save to db

	// create access_token
	accessToken, err := createAccessToken(&user, jwtAccessTokenSecret, jwtAccessTokenExpire)
	if err != nil {
		log.Fatal(err)
		return
	}

	// create refresh_token
	refreshToken, err := createRefreshToken(&user, jwtRefreshTokenSecret, jwtRefreshTokenExpire)
	if err != nil {
		log.Fatal(err)
		return
	}

	signupResponse := SignupResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	ctx.JSON(http.StatusOK, signupResponse)
}

func signinHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"msg": "login",
	})
}

func profileHandler(ctx *gin.Context) {
	userID := ctx.GetString("x-user-id")

	ctx.JSON(http.StatusOK, gin.H{
		"msg":    "profile",
		"userID": userID,
	})
}

func createAccessToken(user *User, secret string, expiry int) (accessToken string, err error) {
	exp := time.Now().Add(time.Hour * time.Duration(expiry))
	claims := JwtCustomClaims{
		ID:   user.ID.Hex(),
		Name: user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func createRefreshToken(user *User, secret string, expiry int) (refreshToken string, err error) {
	exp := time.Now().Add(time.Hour * time.Duration(expiry))
	claimsRefresh := JwtCustomRefreshClaims{
		ID: user.ID.Hex(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	token, err := tokenClaims.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func isAuthorized(tokenString, secret string) (bool, error) {
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

func extractIDFromToken(tokenString, secret string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return "", fmt.Errorf("invalid claims: %v", token.Claims)
	}

	return claims["id"].(string), nil
}
