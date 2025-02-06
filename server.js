import express from "express";
import mySql from "mysql2/promise"
import { env } from "process";
import bcrypt from "bcrypt"; //TO save the passwords encryptly
import { config } from "dotenv";
import bodyParser from "body-parser";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
config();



const AppPort = process.env.AppPort || 8080;
const app = express();

const saltRounds = await bcrypt.genSalt(10);; //More the saltrounds, stronger the hashing is done in password. But this is sufficient for us


app.use(bodyParser.urlencoded({ extended: false })); // Parse form data

app.use(session({
  secret: "HS",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 10 } // 10 minutes
}));
app.use(passport.initialize()); // Initialize Passport
app.use(passport.session()); // Persist sessions
app.use(express.json());




async function activateDb(){
  let conn;
  try{
    conn = await mySql.createConnection({
      host: process.env.db_host,
      database: process.env.db_name,
      user: process.env.db_user,
      password: process.env.db_password,
      port: process.env.db_port,
    });
    console.log(`Connection Successwith DB`);
    return conn;
  }
  catch(error){
    console.log(`Unable to Connect with Db, ${error.stack}`);
    throw error;
  }
}

//TO LOAD THE HOME PAGE OF WEB APPLICATION
app.get('/', async(req, res)=>{
  res.render('HomePage.ejs');
});

//TO OPEN REGISTRATION PAGE
app.get('/student_register', async(req,res)=>{

  const conn = await activateDb();
  try{
    let result = await conn.query(`SELECT * FROM courses`);
    conn.end();
    console.log(result[0]);
    res.render("registrationPage.ejs", {courses: result[0]});
  }
  catch(err){
    console.log("Error While Fetching courses " + err.stack);
    res.status(403).send("Unable to Connect to DB");
  }

});


//TO SAVE THA DATA OF NEWLY REGISTERED STUDENTS AND CHECKING IF HE IS REALLY NEW OR EXISTING ONE WITH PRIMARY KEY AS AADHAR
app.post('/submit' ,async (req, res)=>{
  console.log(req.body);
  let data = req.body;
  const conn = await activateDb();

  try{
    let duplicateData = await conn.query(`SELECT roll_no FROM students where aadhar_no = "${data.aadhar_no}" LIMIT 1`);
    if(duplicateData[0].length > 0){
      let [{roll_no}] = duplicateData[0];
      console.log(duplicateData);
      res.send(`<h1>Student with Same ID already exists with Roll NO. ${roll_no}</h1>`);
    }
    else{
        try{
          let result = await conn.query(`INSERT INTO students VALUES(${null}, "${data.f_name.toUpperCase()}", "${data.l_name.toUpperCase()}", "${data.dob}", "${data.father_name.toUpperCase()}", "${data.mother_name.toUpperCase()}", "${data.gender}", ${data.course}, "${data.contact_no}", "${data.email_add.toLowerCase()}", "${data.aadhar_no}", "${data.house_no}", "${data.street_add}" , "${data.city}", "${data.distt}", "${data.state}", "${data.country}", "${data.pin_code}", ${data.sem})`);
          try{
            let result = await conn.query(`SELECT roll_no FROM students WHERE aadhar_no = ${data.aadhar_no}`);
            let assign_roll_no = result[0][0].roll_no;
            console.log(assign_roll_no);

            try{
              let pass = (data.f_name).substr(0, 4).toUpperCase() + (data.dob).substr(0,4) + (data.pin_code) + (data.aadhar_no).substr(8, 11);

              console.log(pass);
              try{
                pass = await bcrypt.hash(pass, saltRounds);
              }
              catch(error){
                console.log(`Unable to hash the password`);
                res.send(`Unable to create a account, rest assured Registration Success with ${assign_roll_no}.`);
              }
              console.log(pass);

              let result1 = await conn.query(`INSERT INTO studentCred VALUES(${assign_roll_no}, "${pass}")`);
              res.send(`Registered Successfully with Roll Number ${assign_roll_no}. Login Now with your Roll Number (${assign_roll_no}) & use [4 Character of First Name] + [YYYY (from DOB)] + [Pin Code] + [Last 4 Digits of Aadhar]  as Your Password.`);
              conn.end();
            }
            catch(error){
              res.send(`Unable to Register Your Account, Rest Assured, Your Registration is Successful with Roll Number : ${assign_roll_no}`);
            }
          }
          catch(error){
            res.send(`Thank You for Registration, It's Taking Longer than Usual, Try after Some time.`)
          }
        }

        catch(err){
          res.status(500).send("Unable to register" + err.stack);
        }
    }
  }
  catch(err){
    res.status(500).send("Unable to Validate Details" + err.stack);
  }
});



function ensureAuthenticated(req, res, next){ //middleware to ensure session is still established
  if(req.isAuthenticated()){
    return next();
  }
  res.redirect('/');
}



//Student Side
app.get('/stu_login', (req,res)=>{
  res.render('SignIn_Stu.ejs');
});



//TO verify the login credential of the users
app.post('/verify_stu_login', passport.authenticate('student-local', {failureRedirect: '/stu_login'}), (req, res)=>{
  res.redirect('/student_dashboard');
});




app.get('/student_dashboard', ensureAuthenticated, (req, res)=>{
  if(req.user.role === 'student'){
    console.log(`This data is being sent to student dashboard page inially ${JSON.stringify(req.user)}`);
    res.render('student_dashboard.ejs', {user: req.user});
  }
  else{
    res.redirect('/');
  }
});





//Teacher side
app.get('/teach_login', (req,res)=>{
  res.render('SignIn_Teach.ejs');
});




//TO verify the login credential of the users
app.post('/verify_teach_login', passport.authenticate('teacher-local', {failureRedirect: '/stu_login'}), (req, res)=>{
  console.log('techer Authenitcation Success');
  res.redirect('/teacher_dashboard');
});




app.get('/teacher_dashboard', ensureAuthenticated, (req, res)=>{
  if(req.user.role === 'teacher'){
    console.log(`This data is being sent to teacher dashboard page inially ${req.user}`);
    res.render('teacher_dashboard.ejs', {user: req.user});
  }
  else{
    res.redirect('/');
  }
});




app.get('/mark_attendance', ensureAuthenticated, (req,res)=>{
  if(req.user.role === 'teacher'){
    res.render('mark_attendance.ejs', {user: req.user});
  }
  else{
    res.redirect('/');
  }
});




app.get('/getStudents', async (req, res) => {
  const { stream, sem } = req.query; // Extract query parameters
  console.log(`Stream: ${stream}, Semester: ${sem}`); // Log for debugging

  try {
    const conn = await activateDb(); // Connect to the database
    // Use stream and sem to fetch students
    const [result] = await conn.query(
      `SELECT roll_no, first_name, last_name FROM students WHERE sem = ? AND course_id = ?`,
      [sem, stream]
    );
    conn.end();

    if (result.length > 0) {
      res.json(result); // Return student data
    } else {
      res.json([]); // Return an empty array if no students found
    }
  } catch (error) {
    console.error('Error fetching students:', error.message);
    res.status(500).json({ error: 'An error occurred while fetching students.' });
  }
});


app.get('/getSubjects', async(req,res)=>{
  const {stream, sem} = req.query;
  console.log(`Fetching Subjects & got credntial: Course_id ${stream} Sem: ${sem}`);
  try{
    const conn = await activateDb();
    let result = await conn.query(`SELECT sub_id, name FROM subjects WHERE course_id = "${stream}" AND sem = "${sem}"`);
    conn.end();
    res.json({subjects: result[0]});
  }
  catch(error){
    res.json({error: "Unable to Fetch Subjects."})
  }
});






app.post('/submitAttendance', ensureAuthenticated, async (req, res) => {
  
  const attendanceData = req.body;
  console.log("Received attendance data:", attendanceData); // Log the received data

  if (!attendanceData || !Array.isArray(attendanceData) || attendanceData.length === 0) {
    console.error("Invalid attendance data received."); // Log error for invalid data
    return res.status(400).json({ success: false, message: "Invalid attendance data." });
  }

  try {
    const conn = await activateDb();
    console.log("Database connection established."); // Log successful DB connection

    const promises = attendanceData.map((entry) => {
      const { roll_no, status, sub_name, faculty_id, faculty_name } = entry;

      // Log each entry being processed
      console.log("Processing entry:", entry);

      if (!roll_no || !status || !sub_name || !faculty_id || !faculty_name) {
        console.error("Incomplete attendance entry:", entry); // Log incomplete entry
        throw new Error("Incomplete attendance entry.");
      }

      return conn.query(
        `INSERT INTO attendance (roll_no, status, subject_name, faculty_id, faculty_name, att_date) VALUES (?, ?, ?, ?, ?, NOW())`,
        [roll_no, status, sub_name, faculty_id, faculty_name]
      );
    });

    await Promise.all(promises);
    console.log("All attendance entries have been successfully saved."); // Log success

    res.status(200).json({ success: true, message: "Attendance submitted successfully!" });
  } catch (error) {
    console.error("Error saving attendance:", error); // Log the error
    res.status(500).json({ success: false, message: "Error saving attendance. Please try again." });
  }
});


app.get('/attendanceCorrection', ensureAuthenticated, async(req, res)=>{
  res.render('correct_attendance.ejs', {user: req.user});
});


app.get('/getAttendanceById', ensureAuthenticated, async (req, res) => {
  const { id } = req.query;

  try {
    const conn = await activateDb();
    const [rows] = await conn.query(
      `SELECT * FROM attendance WHERE attend_id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return res.json({ error: "Attendance ID not found." });
    }

    const attendance = rows[0];

    // Ensure faculty ID matches
    if (attendance.faculty_id !== req.user.id) {
      return res.json({ error: "You are not authorized to modify this attendance record." });
    }

    res.json(attendance);
  } catch (error) {
    console.error("Error fetching attendance:", error);
    res.status(500).json({ error: "Failed to fetch attendance." });
  }
});



app.post('/updateAttendance', ensureAuthenticated, async (req, res) => {
  const { att_id, status } = req.body;

  try {
    const conn = await activateDb();

    // Verify faculty ownership before updating
    const [rows] = await conn.query(
      `SELECT * FROM attendance WHERE attend_id = ?`,
      [att_id]
    );

    if (rows.length === 0) {
      return res.json({ error: "Attendance ID not found." });
    }

    const attendance = rows[0];

    if (attendance.faculty_id !== req.user.id) {
      return res.json({ error: "You are not authorized to modify this attendance record." });
    }

    // Update attendance
    await conn.query(
      `UPDATE attendance SET status = ? WHERE attend_id = ?`,
      [status, att_id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error("Error updating attendance:", error);
    res.status(500).json({ error: "Failed to update attendance." });
  }
});



app.get('/getAttendance', ensureAuthenticated, async (req, res) => {
  const { roll_no, subject } = req.query;

  if (!roll_no) {
    return res.status(400).json({ error: "Roll number is required." });
  }

  try {
    let query = `
      SELECT attend_id, subject_name, subject_name, status, faculty_name, att_date
      FROM attendance
      WHERE roll_no = ?
    `;
    const params = [roll_no];

    if (subject) {
      console.log("Specific sub req: " + subject);
      query += ` AND subject_name = ?`;
      params.push(subject);
    }
    const conn = await activateDb();

    const [attendanceRecords] = await conn.query(query, params);

    if (attendanceRecords.length === 0) {
      return res.status(404).json({ error: "No attendance data found." });
    }

    res.json({ attendance: attendanceRecords });
  } catch (error) {
    console.error("Error fetching attendance:", error);
    res.status(500).json({ error: "Failed to fetch attendance." });
  }
});




app.get('/parents', async(req, res)=>{
  res.render('parents.ejs');
});


app.get('/getFullAttendance', async (req, res) => {
  const { roll_no } = req.query;

  if (!roll_no) {
    return res.status(400).json({ error: 'Roll number is required.' });
  }

  try {
    const conn = await activateDb();
    const query = `SELECT att_date, subject_name, status FROM attendance WHERE roll_no = "${roll_no}" ORDER BY att_date DESC`;
      const [rows] = await conn.query(query);
      conn.end();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No attendance records found for this roll number.' });
    }
    res.json({ attendance: rows });
  } catch (error) {
    console.error('Error fetching attendance:', error);
    res.status(500).json({ error: 'Internal server error. Please try again later.' });
  }
});




app.listen(AppPort, ()=>{
  console.log(`App is listening at the PORT ${AppPort}`);
  console.log(`http://localhost:${AppPort}`);

});








passport.use(
  'student-local',
  new Strategy(
    { usernameField: 'username', passwordField: 'password', passReqToCallback: true },
    async (req, username, password, done) => {
      try {
        const conn = await activateDb();
        const [rows] = await conn.query(`SELECT * FROM studentCred WHERE roll_no = ?`, [username]);
        conn.end();

        if (rows.length === 0) {
          return done(null, false, { message: `User doesn't exist! Please register first.` });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (match) {
          user.role = req.body.role; // Attach role
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      } catch (error) {
        console.error('Error during authentication:', error.message);
        return done(error);
      }
    }
  )
);




passport.use(
  'teacher-local',
  new Strategy(
    { usernameField: 'username', passwordField: 'password', passReqToCallback: true },
    async (req, username, password, done) => {
      try {
        const conn = await activateDb();
        const [rows] = await conn.query(`SELECT * FROM faculty WHERE id = ?`, [username]);
        conn.end();

        if (rows.length === 0) {
          return done(null, false, { message: `User doesn't exist! Please register first.` });
        }

        const user = rows[0];
        if (user.password === password) {
          user.role = req.body.role; // Attach role
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      } catch (error) {
        console.error('Error during authentication:', error.message);
        return done(error);
      }
    }
  )
);






passport.serializeUser((user, done) => {
  const key = { id: user.roll_no || user.id, role: user.role };
  console.log(`Serializer Key: ${JSON.stringify(key)}`);
  done(null, key);
});



passport.deserializeUser(async (key, done) => {
  const { id, role } = key;

  let query;
  if (role === 'student') {
    query = `SELECT * FROM students WHERE roll_no = ?`;
  } else if (role === 'teacher') {
    query = `SELECT * FROM faculty WHERE id = ?`;
  }

  try {
    const conn = await activateDb();
    const [rows] = await conn.query(query, [id]);
    conn.end();

    if (rows.length > 0) {
      rows[0].role = role; // Reattach role
      done(null, rows[0]);
    } else {
      done(null, false);
    }
  } catch (error) {
    console.error('Error during deserialization:', error.message);
    done(error);
  }
});