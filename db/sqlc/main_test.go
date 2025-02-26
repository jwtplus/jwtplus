package db

import (
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"
	"github.com/spf13/viper"
)

var testQueries *Queries

func TestMain(m *testing.M) {

	pathConfig, err := filepath.Abs(filepath.Join("..", ".."))
	fmt.Println(pathConfig)
	if err != nil {
		log.Fatalf("Failed to get path: %v", err)
		return
	}

	config := viper.New()
	config.SetConfigName("dev")
	config.AddConfigPath(pathConfig)
	config.SetConfigType("env")

	err = config.ReadInConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		config.GetString("TEST_DB_USER"),
		config.GetString("TEST_DB_PASSWORD"),
		config.GetString("TEST_DB_HOST"),
		config.GetString("TEST_DB_PORT"),
		config.GetString("TEST_DB_NAME"),
	)
	dbCon, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}

	err = dbCon.Ping()
	if err != nil {
		log.Fatalf("Failed to ping to test database: %v", err)
	}

	testQueries = New(dbCon)
	exitCode := m.Run()
	dbCon.Close()
	os.Exit(exitCode)
}

func GenUlid() string {
	entropy := rand.New(rand.NewSource(time.Now().UnixNano()))
	ms := ulid.Timestamp(time.Now())
	u, _ := ulid.New(ms, entropy)
	return u.String()
}

func GetSHA512Hash(txt string) string {
	h := sha512.New()
	h.Write([]byte(txt))
	sha := h.Sum(nil)
	return hex.EncodeToString(sha)
}
