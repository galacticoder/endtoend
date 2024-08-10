#include <sqlite3.h>
#include <iostream>
#include <string>

//g++ -o sqlite_example sqlite_example.cpp -lsqlite3

int main() {
    sqlite3* db;
    char* errMsg = 0;
    int rc;

    // db connect
    rc = sqlite3_open("test.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    } else {
        std::cout << "Opened database successfully" << std::endl;
    }

    std::string sql = "CREATE TABLE IF NOT EXISTS PERSON("  \
                      "ID INT PRIMARY KEY NOT NULL," \
                      "NAME TEXT NOT NULL," \
                      "AGE INT NOT NULL);";
    
    rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Table created successfully" << std::endl;
    }

    // add
    sql = "INSERT INTO PERSON (ID, NAME, AGE) " \
          "VALUES (1, 'John Doe', 30);";
    rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Record created successfully" << std::endl;
    }

    // look for
    sql = "SELECT * FROM PERSON;";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char* name = sqlite3_column_text(stmt, 1);
            int age = sqlite3_column_int(stmt, 2);
            std::cout << "ID: " << id << ", Name: " << name << ", Age: " << age << std::endl;
        }
    } else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);

    // close
    sqlite3_close(db);
    return 0;
}
