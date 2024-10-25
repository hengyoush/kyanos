import mysql.connector  
import time
import sys
from mysql.connector import Error  
  
def create_connection(host_name, user_name, user_password):  
    connection = None  
    try:  
        connection = mysql.connector.connect(  
            host=host_name,  
            user=user_name,  
            passwd=user_password  
        )  
        print("Connection to MySQL server successful")  
    except Error as e:  
        print(f"The error '{e}' occurred")  
      
    return connection  
  
def create_database(connection, database_name):  
    cursor = connection.cursor()  
    try:  
        cursor.execute(f"CREATE DATABASE {database_name}")  
        print(f"Database '{database_name}' created successfully")  
    except Error as e:  
        print(f"The error '{e}' occurred")  
  
def execute_query_in_database(connection, database_name, query, count):  
    try:  
        cursor = connection.cursor()  
        cursor.execute(f"USE {database_name}")  
        for i in range(count):
            cursor.execute(query)  
            
            # If it's a SELECT statement, fetch the results  
            if query.strip().upper().startswith('SELECT'):  
                result = cursor.fetchall()  
                for row in result:  
                    print(row)  
            else:  
                # For other statements like INSERT, UPDATE, DELETE, commit the transaction  
                connection.commit()  
                print("Query executed successfully")  
            # 休眠
            time.sleep(0.5)
          
    except Error as e:  
        print(f"The error '{e}' occurred")  
  
count = int(sys.argv[1])
# Replace with your MySQL server credentials  
connection = create_connection("localhost", "root", "123456")  
  
# Database name to be created  
database_name = "test"  
  
# Create the database  
create_database(connection, database_name)  
  
# Example SQL query to execute in the newly created database  
query = "CREATE TABLE example_table (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100))"  
execute_query_in_database(connection, database_name, query,1)  
  
# Another example query to insert data  
insert_query = "INSERT INTO example_table (name) VALUES ('John Doe')"  
execute_query_in_database(connection, database_name, insert_query,1)  
  
# Example SELECT query to retrieve data  
select_query = "SELECT * FROM example_table"  
execute_query_in_database(connection, database_name, select_query, count) 
  
time.sleep(1)
# Close the connection  
if connection.is_connected():  
    connection.close()  
    print("The connection is closed")