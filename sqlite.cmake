# https://sqlite.org/index.html
# Building shell: gcc shell.c sqlite3.c -lpthread
# static library:
# gcc -O3 -c sqlite3.c -o sqlite.o
# ar rcs libsqlite3.a sqlite.o
#
# cl /c /EHsc sqlite3.c
# lib sqlite3.obj
#
# dynamic library:
# gcc -O3 -shared sqlite.c -o sqlite3.dll
# cl sqlite3.c -link -dll -out:sqlite3.dll

add_definitions("-DQT_NO_KEYWORDS")
if(WIN32)
    include_directories("C:/Components/SQLite-3.42.0")
    link_directories("C:/Components/SQLite-3.42.0")
endif()

link_libraries("sqlite3")
