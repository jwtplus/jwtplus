package lib

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

func DBConnect() (*sql.DB, error) {
	var dsn string

	dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		Config.GetString("db.username"),
		Config.GetString("db.password"),
		Config.GetString("db.location"),
		Config.GetString("db.port"),
		Config.GetString("db.dbname"),
	)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}
