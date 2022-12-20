package controller

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"os"
	"strconv"
	"strings"
	"time"
)

type Controller interface {
	AuthMiddleware(context *gin.Context)

	Register(*gin.Context)
	Login(*gin.Context)

	GetPlace(*gin.Context)
	GetPlaces(*gin.Context)
	CreatePlace(*gin.Context)
	DeletePlace(*gin.Context)

	GetRoom(*gin.Context)
	GetRooms(*gin.Context)
	GetRoomImage(*gin.Context)
	CreateRoom(*gin.Context)
	DeleteRoom(*gin.Context)

	GetDevice(*gin.Context)
	GetDevices(*gin.Context)
	UpdateDevice(*gin.Context)
	CreateDevice(*gin.Context)
	DeleteDevice(*gin.Context)
}

type controller struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func (c controller) UpdateDevice(context *gin.Context) {
	deviceId := context.Param("deviceId")

	var oldDevice Device
	if err := c.db.Where(
		"id = ?", deviceId,
	).First(&oldDevice).Error; err != nil {
		c.sugar.Errorw("failed to get device", err)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "failed to get device",
			},
		)
		return
	}

	newState := context.PostForm("state")
	if newState != "" {
		oldDevice.State = newState
	}

	newPositionX := context.PostForm("positionX")
	if newPositionX != "" {
		newPositionXInt, _ := strconv.Atoi(newPositionX)
		oldDevice.PositionX = newPositionXInt
	}

	newPositionY := context.PostForm("positionY")
	if newPositionY != "" {
		newPositionYInt, _ := strconv.Atoi(newPositionY)
		oldDevice.PositionY = newPositionYInt
	}

	if err := c.db.Save(&oldDevice).Error; err != nil {
		c.sugar.Errorw("failed to update device", err)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "failed to update device",
			},
		)
		return
	}

	context.JSON(
		200, gin.H{
			"message": "device updated",
		},
	)

}

func (c controller) AuthMiddleware(context *gin.Context) {
	token := context.GetHeader("Authorization")
	if token == "" {
		context.Next()
		return
	}

	tokenSplit := strings.Split(token, " ")
	if len(tokenSplit) != 2 {
		context.JSON(
			401, gin.H{
				"message": "invalid authorization header",
			},
		)
		context.Abort()
		return
	}

	if tokenSplit[0] != "Bearer" {
		context.JSON(
			401, gin.H{
				"message": "unsupported authorization type",
			},
		)
		context.Abort()
		return
	}

	token = tokenSplit[1]

	username, err := verifyJWT(token)
	if err != nil {
		context.JSON(
			401, gin.H{
				"message": "invalid token",
			},
		)
		context.Abort()
		return
	}

	context.Set("username", username)
}

type User struct {
	gorm.Model
	Username     string `json:"username" gorm:"primaryKey"`
	Phone        string `json:"phone"`
	PasswordHash string `json:"passwordHash"`
	Nickname     string `json:"nickname"`
	Email        string `json:"email"`
}

type Place struct {
	gorm.Model
	ID    uint   `gorm:"primaryKey" json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type Room struct {
	gorm.Model
	ID      uint   `gorm:"primaryKey" json:"id"`
	Name    string `json:"name"`
	PlaceID uint   `json:"placeId"`
}

type Device struct {
	gorm.Model
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`
	RoomID    uint   `json:"roomId"`
	Type      string `json:"type"`
	State     string `json:"state"`
	PositionX int    `json:"positionX"`
	PositionY int    `json:"positionY"`
}

func New(sugar *zap.SugaredLogger) Controller {

	mysqlUser := os.Getenv("MYSQL_USERNAME")
	if mysqlUser == "" {
		panic("MYSQL_USERNAME is not set")
	}

	mysqlPass := os.Getenv("MYSQL_PASSWORD")
	if mysqlPass == "" {
		panic("MYSQL_PASSWORD is not set")
	}

	mysqlHost := os.Getenv("MYSQL_HOST")
	if mysqlHost == "" {
		panic("MYSQL_HOST is not set")
	}

	mysqlPort := os.Getenv("MYSQL_PORT")
	if mysqlPort == "" {
		panic("MYSQL_PORT is not set")
	}

	mysqlDatabase := os.Getenv("MYSQL_DATABASE")
	if mysqlDatabase == "" {
		panic("MYSQL_DATABASE is not set")
	}

	dsn := mysqlUser + ":" + mysqlPass + "@tcp(" + mysqlHost + ":" + mysqlPort + ")/" + mysqlDatabase + "?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(
		mysql.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		},
	)
	if err != nil {
		panic(err)
	}

	if err = db.AutoMigrate(&User{}); err != nil {
		panic(err)
	}

	if err = db.AutoMigrate(&Place{}); err != nil {
		panic(err)
	}

	if err = db.AutoMigrate(&Room{}); err != nil {
		panic(err)
	}

	if err = db.AutoMigrate(&Device{}); err != nil {
		panic(err)
	}

	return &controller{db, sugar}
}

func (c controller) signJWT(username string) (string, error) {
	now := time.Now()
	jwtId := username + strconv.FormatInt(now.Unix(), 10)
	claims := jwt.StandardClaims{
		Audience:  username,
		ExpiresAt: 0,
		Id:        jwtId,
		IssuedAt:  now.Unix(),
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		panic("JWT_SECRET is not set")
	}

	token, err := tokenClaims.SignedString([]byte(jwtSecret))
	if err != nil {
		c.sugar.Errorw("failed to sign jwt", err)
		return "", err
	}

	return token, nil
}

func verifyJWT(s string) (string, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		panic("JWT_SECRET is not set")
	}

	r, err := jwt.ParseWithClaims(
		s, &jwt.StandardClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, nil
			}
			return []byte(jwtSecret), nil
		},
	)

	if err != nil || !r.Valid {
		return "", err
	}

	claims, ok := r.Claims.(*jwt.StandardClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse claims")
	}

	return claims.Audience, nil
}

func (c controller) Register(context *gin.Context) {
	username := context.PostForm("username")
	if username == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "username is empty",
			},
		)
		return
	}

	phone := context.PostForm("phone")
	if phone == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "phone is empty",
			},
		)
		return
	}

	password := context.PostForm("password")
	if password == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "password is empty",
			},
		)
		return
	}

	nickname := context.PostForm("nickname")
	if nickname == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "nickname is empty",
			},
		)
		return
	}

	email := context.PostForm("email")
	if email == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "email is empty",
			},
		)
		return
	}

	var user User
	c.db.Where("username = ?", username).First(&user)
	if user.Username != "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "username already exists",
			},
		)
		return
	}

	c.db.Where("phone = ?", phone).First(&user)
	if user.Phone != "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "phone has been registered by another user",
			},
		)
		return
	}

	c.db.Where("email = ?", email).First(&user)
	if user.Email != "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "email has been registered by another user",
			},
		)
		return
	}

	passHash, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost,
	)
	if err != nil {
		c.sugar.Errorw("failed to hash password", "error", err)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	v := c.db.Create(
		&User{
			Username:     username,
			Phone:        phone,
			PasswordHash: string(passHash),
			Nickname:     nickname,
			Email:        email,
		},
	)

	if v.Error != nil {
		c.sugar.Errorw("failed to create user", "error", v.Error)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	token, err := c.signJWT(username)
	if err != nil {
		c.sugar.Errorw("failed to sign jwt", "error", err)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(200, gin.H{"token": token})
}

func (c controller) Login(context *gin.Context) {
	username := context.PostForm("username")
	if username == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "username is empty",
			},
		)
		return
	}

	password := context.PostForm("password")
	if password == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "password is empty",
			},
		)
		return
	}

	var user User
	c.db.Where("username = ?", username).First(&user)
	if user.Username == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "username not found",
			},
		)
		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash), []byte(password),
	); err != nil {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "password is incorrect",
			},
		)
		return
	}

	token, err := c.signJWT(username)
	if err != nil {
		c.sugar.Errorw("failed to sign jwt", "error", err)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(200, gin.H{"token": token})
}

func (c controller) GetPlace(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	placeId := context.Param("placeId")
	if placeId == "" {
		context.JSON(
			400, gin.H{
				"message": "placeId is empty",
			},
		)
		return
	}

	type PlaceWithRoomCount struct {
		Place
		RoomCount int `json:"roomCount"`
	}

	var place PlaceWithRoomCount

	c.db.Table("places").
		Select("places.*, COUNT(rooms.id) AS room_count").
		Joins("LEFT JOIN rooms ON rooms.place_id = places.id").
		Where("places.id = ?", placeId).
		Group("places.id").
		First(&place)

	if place.ID == 0 {
		context.AbortWithStatusJSON(
			404, gin.H{
				"message": "place not found",
			},
		)
		return
	}

	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	context.JSON(200, place)
}

func (c controller) GetPlaces(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	if owner == "" {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	type PlaceWithRoomCount struct {
		Place
		RoomCount int `json:"roomCount"`
	}

	var places []PlaceWithRoomCount
	c.db.Table("places").
		Select("places.*, COUNT(rooms.id) AS room_count").
		Joins("LEFT JOIN rooms ON rooms.place_id = places.id").
		Where("places.owner = ?", owner).
		Group("places.id").
		Find(&places)

	context.JSON(200, places)
}

func (c controller) CreatePlace(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	name := context.PostForm("name")
	if name == "" {
		context.JSON(
			400, gin.H{
				"message": "name is empty",
			},
		)
		return
	}

	var place Place
	c.db.Where("name = ? AND owner = ?", name, owner).First(&place)
	if place.Name != "" {
		context.JSON(
			400, gin.H{
				"message": "place name has been used",
			},
		)
		return
	}

	create := c.db.Create(
		&Place{
			Name:  name,
			Owner: owner.(string),
		},
	)
	if create.Error != nil {
		c.sugar.Errorw("failed to create place", "error", create.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	created := Place{}
	c.db.Where("name = ? AND owner = ?", name, owner).First(&created)

	context.JSON(201, created)
}

func (c controller) DeletePlace(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	placeId := context.Param("placeId")
	if placeId == "" {
		context.JSON(
			400, gin.H{
				"message": "placeId is empty",
			},
		)
		return
	}

	var place Place
	c.db.Where("id = ?", placeId).First(&place)
	if place.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "place not found",
			},
		)
		return
	}

	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	del := c.db.Delete(&place)
	if del.Error != nil {
		c.sugar.Errorw("failed to delete place", "error", del.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(204, gin.H{})
}

func (c controller) GetRoom(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	roomId := context.Param("roomId")
	if roomId == "" {
		context.JSON(
			400, gin.H{
				"message": "roomId is empty",
			},
		)
		return
	}

	type RoomWithDeviceCount struct {
		Room
		DeviceCount int `json:"deviceCount"`
	}

	var room RoomWithDeviceCount
	c.db.Table("rooms").
		Select("rooms.*, COUNT(devices.id) AS device_count").
		Joins("LEFT JOIN devices ON devices.room_id = rooms.id").
		Where("rooms.id = ?", roomId).
		Group("rooms.id").
		First(&room)

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.AbortWithStatusJSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	context.JSON(200, room)
}

func (c controller) GetRooms(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	placeId := context.Param("placeId")
	if placeId == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "placeId is empty",
			},
		)
		return
	}

	var place Place
	c.db.Where("id = ?", placeId).First(&place)
	if place.ID == 0 {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "place not found",
			},
		)
		return
	}

	if place.Owner != owner {
		context.AbortWithStatusJSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	type RoomWithDeviceCount struct {
		Room
		DeviceCount int `json:"deviceCount"`
	}

	var rooms []RoomWithDeviceCount
	c.db.Table("rooms").
		Select("rooms.*, COUNT(devices.id) AS device_count").
		Joins("LEFT JOIN devices ON devices.room_id = rooms.id").
		Where("rooms.place_id = ?", placeId).
		Group("rooms.id").
		Find(&rooms)

	if len(rooms) == 0 {
		context.JSON(200, []Room{})
		return
	}

	context.JSON(200, rooms)
}

func (c controller) CreateRoom(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	placeId := context.Param("placeId")
	if placeId == "" {
		context.JSON(
			400, gin.H{
				"message": "placeId is empty",
			},
		)
		return
	}

	var place Place
	c.db.Where("id = ?", placeId).First(&place)
	if place.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "place not found",
			},
		)
		return
	}

	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	name := context.PostForm("name")
	if name == "" {
		context.JSON(
			400, gin.H{
				"message": "name is empty",
			},
		)
		return
	}

	var room Room
	c.db.Where("name = ? AND place_id = ?", name, placeId).First(&room)
	if room.Name != "" {
		context.JSON(
			400, gin.H{
				"message": "room name has been used",
			},
		)
		return
	}

	create := c.db.Create(&Room{Name: name, PlaceID: place.ID})
	if create.Error != nil {
		c.sugar.Errorw("failed to create room", "error", create.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	created := Room{}
	c.db.Where("name = ? AND place_id = ?", name, placeId).First(&created)

	roomImage, err := context.FormFile("image")
	if err != nil {
		context.JSON(
			400, gin.H{
				"message": "roomImage is empty",
			},
		)
		return
	}

	roomIDString := strconv.Itoa(int(created.ID))
	roomImageName := fmt.Sprintf("place-%s-room-%s.jpg", placeId, roomIDString)
	if err := context.SaveUploadedFile(roomImage, roomImageName); err != nil {
		c.sugar.Errorw("failed to save room image", "error", err)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(201, created)
}

func (c controller) GetRoomImage(context *gin.Context) {
	placeId := context.Param("placeId")
	roomId := context.Param("roomId")
	roomImagePath := fmt.Sprintf("place-%s-room-%s.jpg", placeId, roomId)
	context.File(roomImagePath)
}

func (c controller) DeleteRoom(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	roomId := context.Param("roomId")
	if roomId == "" {
		context.JSON(
			400, gin.H{
				"message": "roomId is empty",
			},
		)
		return
	}

	var room Room
	c.db.Where("id = ?", roomId).First(&room)
	if room.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "room not found",
			},
		)
		return
	}

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	del := c.db.Delete(&room)
	if del.Error != nil {
		c.sugar.Errorw("failed to delete room", "error", del.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(204, gin.H{})
}

func (c controller) GetDevice(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	deviceId := context.Param("deviceId")
	if deviceId == "" {
		context.JSON(
			400, gin.H{
				"message": "deviceId is empty",
			},
		)
		return
	}

	var device Device
	c.db.Where("id = ?", deviceId).First(&device)
	if device.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "device not found",
			},
		)
		return
	}

	room := Room{}
	c.db.Where("id = ?", device.RoomID).First(&room)
	if room.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "room not found",
			},
		)
		return
	}

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	context.JSON(200, device)
}

func (c controller) GetDevices(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	roomId := context.Param("roomId")
	if roomId == "" {
		context.JSON(
			400, gin.H{
				"message": "roomId is empty",
			},
		)
		return
	}

	var room Room
	c.db.Where("id = ?", roomId).First(&room)
	if room.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "room not found",
			},
		)
		return
	}

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	var devices []Device
	find := c.db.Where("room_id = ?", roomId).Find(&devices)
	if find.Error != nil {
		c.sugar.Errorw("failed to find devices", "error", find.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(200, devices)
}

func (c controller) CreateDevice(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	roomId := context.Param("roomId")
	if roomId == "" {
		context.JSON(
			400, gin.H{
				"message": "roomId is empty",
			},
		)
		return
	}

	var room Room
	c.db.Where("id = ?", roomId).First(&room)
	if room.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "room not found",
			},
		)
		return
	}

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.JSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	name := context.PostForm("name")
	if name == "" {
		context.JSON(
			400, gin.H{
				"message": "name is empty",
			},
		)
		return
	}

	var device Device
	c.db.Where("name = ? AND room_id = ?", name, roomId).First(&device)
	if device.Name != "" {
		context.JSON(
			400, gin.H{
				"message": "device name has been used",
			},
		)
		return
	}

	deviceType := context.PostForm("type")
	if deviceType == "" {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "type is empty",
			},
		)
		return
	}

	stateString := "{}"
	switch deviceType {
	case "light":
		stateString = `{"status": "off", "lightness": 0}`
	case "lock":
		stateString = `{"status": "unlocked"}`
	case "switch":
		stateString = `{"status": "off"}`
	case "sensor":
		stateString = `{"value": 30}`
	}

	create := c.db.Create(
		&Device{
			Name:   name,
			RoomID: room.ID,
			Type:   deviceType,
			State:  stateString,
		},
	)
	if create.Error != nil {
		c.sugar.Errorw("failed to create device", "error", create.Error)
		context.JSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	created := Device{}
	c.db.Where("name = ? AND room_id = ?", name, roomId).First(&created)

	context.JSON(201, created)
}

func (c controller) DeleteDevice(context *gin.Context) {
	owner, isLoggedIn := context.Get("username")
	if !isLoggedIn {
		context.AbortWithStatusJSON(
			401, gin.H{"message": "please login"},
		)
		return
	}

	deviceId := context.Param("deviceId")
	if deviceId == "" {
		context.JSON(
			400, gin.H{
				"message": "deviceId is empty",
			},
		)
		return
	}

	var device Device
	c.db.Where("id = ?", deviceId).First(&device)
	if device.ID == 0 {
		context.JSON(
			400, gin.H{
				"message": "device not found",
			},
		)
		context.Abort()
		return
	}

	room := Room{}
	c.db.Where("id = ?", device.RoomID).First(&room)
	if room.ID == 0 {
		context.AbortWithStatusJSON(
			400, gin.H{
				"message": "room not found",
			},
		)
		context.Abort()
		return
	}

	place := Place{}
	c.db.Where("id = ?", room.PlaceID).First(&place)
	if place.Owner != owner {
		context.AbortWithStatusJSON(
			401, gin.H{
				"message": "permission denied",
			},
		)
		return
	}

	del := c.db.Delete(&device)
	if del.Error != nil {
		c.sugar.Errorw("failed to delete device", "error", del.Error)
		context.AbortWithStatusJSON(
			500, gin.H{
				"message": "internal error",
			},
		)
		return
	}

	context.JSON(204, gin.H{})
}
