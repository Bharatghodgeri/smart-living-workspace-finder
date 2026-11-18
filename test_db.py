
from config import get_db_connection

try:
    connection = get_db_connection()

    if connection.is_connected():
        print("Database connected successfully!")

        cursor = connection.cursor()
        cursor.execute("SHOW TABLES")

        print("Tables in smart_living_db:")
        for table in cursor.fetchall():
            print(table[0])

        cursor.close()
        connection.close()

except Exception as error:
    print("Database connection failed:", error)