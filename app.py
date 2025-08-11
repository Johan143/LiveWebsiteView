import os
from flask import Flask, render_template, request, flash, session, redirect
import sqlite3
#super cool functions to generate and check password password hashes
from werkzeug.security import generate_password_hash, check_password_hash

#create app  
app = Flask(__name__)

#secret key is needed for sessions and flash messages
app.config['SECRET_KEY'] = "MySecretKey"

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")

#This query_db function combines getting the databse, cursor, executing and fetching the results
def query_db(sql, args=(), one=False):
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(sql, args)
    results = cursor.fetchall()
    db.commit()
    db.close()
    return (results[0] if results else None) if one else results

# admin page
@app.route("/admin")
def admin():
    # Check if the user is logged in and is an admin
    if 'user' in session and session['user']['role'] == "admin":
        sql = "SELECT Students.ID, Students.Name, Students.Image FROM Students;"
        results = query_db(sql)
        return render_template("admin.html", results = results)
    else:
        flash("You do not have permission to access this page.")
        return redirect("/")
    
# teacher page
@app.route("/teacher/<int:id>")
def teacher(id):
    if 'user' in session and session['user']['role'] == "teacher" and session['user']['id'] == id:
        sql = """
            SELECT YearLevels.Year, Teachers.FirstName
            FROM Courses
            JOIN YearLevels ON Courses.YearLevelID = YearLevels.ID
            JOIN Teachers ON Courses.TeacherID = Teachers.ID
            WHERE Courses.TeacherID = ?;
        """
        years = query_db(sql, (id,))
        return render_template("teacher.html", teacher=session['user'], years=years)

#year page
@app.route("/teacher/<int:id>/year/<int:year>")
def year_levels(id, year):
    if 'user' in session and session['user']['role'] == "teacher" and session['user']['id'] == id:
        sql = """
            SELECT ClassGroups.ID, ClassGroups.Name
            FROM Courses
            JOIN ClassGroups ON Courses.ClassGroupID = ClassGroups.ID
            JOIN YearLevels ON Courses.YearLevelID = YearLevels.ID
            WHERE Courses.TeacherID = ? AND YearLevels.Year = ?
        """
        groups = query_db(sql, (id, year))

        years = """
            SELECT YearLevels.Year, Teachers.FirstName
            FROM Courses
            JOIN YearLevels ON Courses.YearLevelID = YearLevels.ID
            JOIN Teachers ON Courses.TeacherID = Teachers.ID
            WHERE Courses.TeacherID = ?;
        """
        years = query_db(years, (id,))
        return render_template("year_students.html", teacher=session['user'], year=year, groups=groups, years=years)
    else:
        flash("You are not authorized to access this page.")
        return redirect("/")

# groups page
@app.route('/teacher/<int:id>/year/<int:year>/group/<int:group>')
def class_group(id, year, group):
    if 'user' in session and session['user']['role'] == "teacher" and session['user']['id'] == id:
        sql = """
            SELECT Students.ID, Students.Name, Students.Image
            FROM Students
            JOIN StudentCourses ON Students.ID = StudentCourses.StudentID
            JOIN Courses ON StudentCourses.CourseID = Courses.ID
            JOIN YearLevels ON Courses.YearLevelID = YearLevels.ID
            WHERE Courses.TeacherID = ? AND YearLevels.Year = ? AND Courses.ClassGroupID = ?;
        """
        students = query_db(sql, (id, year, group))

        years = """
            SELECT YearLevels.Year, Teachers.FirstName
            FROM Courses
            JOIN YearLevels ON Courses.YearLevelID = YearLevels.ID
            JOIN Teachers ON Courses.TeacherID = Teachers.ID
            WHERE Courses.TeacherID = ?;
        """
        years = query_db(years, (id,))

        return render_template("classgroups.html", teacher=session['user'], year=year, group=group, years=years, students=students)
    else:
        flash("You are not authorized to access this page.")
        return redirect("/")


# home page
@app.route("/")
def home():
    return render_template("home.html")

# student details page
@app.route("/student/<int:id>")
def student(id):
    sql = """SELECT Students.ID, Students.Name, Students.Age, Students.Year, Students.Gender, 
Students.Image, Students.Pronounce, Students.ClassGroupID, Subjects.Name AS Subjects, Teachers.FirstName, 
Teachers.LastName 
FROM Students
JOIN StudentCourses ON Students.ID = StudentCourses.StudentID
JOIN Courses ON StudentCourses.CourseID = Courses.ID
JOIN Subjects ON Courses.SubjectID = Subjects.ID
JOIN Teachers ON Courses.TeacherID = Teachers.ID
WHERE Students.ID = ?;"""
    result = query_db(sql, (id,)) #this query_db is not (sql, (id,) True) because the courses 
                                  # have multiple rows
    return render_template("student_details.html", student = result)

# signup page - when a user signup, their username and password are stored in the database and the password is hashed
@app.route("/signup", methods = ["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        sql = "INSERT INTO User (username, password) VALUES (?, ?);"
        query_db(sql, (username, hashed_password))
        # flash to show that the account was created
        flash("Account created successfully!")
    return render_template("signup.html")

# login page 
@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        sql = """
            SELECT User.id, User.username, User.password, User.role, Teachers.FirstName
            FROM User
            JOIN Teachers ON User.username = Teachers.Username
            WHERE User.username = ?;
        """
        user = query_db(sql=sql, args=(username,), one=True)
        if user:
            if check_password_hash(user[2], password):
                # Overwrite session data with the logged-in user's information
                session.clear()  # Clear any existing session data
                #this store the username in the session
                session['user'] = { 
                    'id': user[0], 
                    'username': user[1],
                    'role': user[3],
                    'first_name': user[4]  # Add this line to store the first name
                    }
                print("Session set:", session)  # Debugging: Check session after login
                #redirect based on role
                if user[3] == "admin":
                    return redirect("/admin")
                elif user[3] == "teacher":
                    return redirect(f"/teacher/{user[0]}") # Redirect to teacher's dashboard
                else:
                    return redirect("/")  # Redirect to home 
            else:
                flash("Password is incorrect")
        else:
            flash("The username does not exist")
    return render_template("home.html")


# logout page
@app.route('/logout')
def logout():
    # Clear all session data
    session.clear() # session.clear removes all data from the session
    print("Session cleared", session)
    flash("You have been logged out.")
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True, port=5191)


