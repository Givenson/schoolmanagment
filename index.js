const express = require('express');
const cors = require('cors');
const db = require('./database');

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

const jwt = require('jsonwebtoken');
const JWT_SECRET = 'qwertyuyfhvfhku'; // In a real app, use an environment variable for this!

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // if there isn't any token

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // if the token is invalid
    req.user = user;
    next();
  });
};

app.get('/', (req, res) => {
  res.send('Hello from the server!');
});

// --- Setup API Endpoints ---

// Check if an admin user exists
app.get('/api/setup/admin-exists', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id FROM users WHERE role = \'admin\' LIMIT 1');
    res.json({ exists: rows.length > 0 });
  } catch (err) {
    console.error('Error checking for admin user:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- User API Endpoints ---

// GET all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM users ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET users by role
app.get('/api/users/role/:role', authenticateToken, async (req, res) => {
  try {
    const { role } = req.params;
    const [rows] = await db.query('SELECT * FROM users WHERE role = ? ORDER BY name', [role]);
    res.json(rows);
  } catch (err) {
    console.error(`Error fetching users with role ${role}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Function to generate a unique 4-digit student ID
const generateUniqueStudentId = async () => {
  let studentId;
  let isUnique = false;
  while (!isUnique) {
    studentId = Math.floor(1000 + Math.random() * 9000).toString();
    const [existing] = await db.query('SELECT id FROM users WHERE student_id = ?', [studentId]);
    if (existing.length === 0) {
      isUnique = true;
    }
  }
  return studentId;
};

const bcrypt = require('bcrypt');
const saltRounds = 10;

// POST a new user
const handleCreateUser = async (req, res) => {
  try {
    const { name, email, role, password } = req.body;
    if (!name || !email || !role || !password) {
      return res.status(400).json({ error: 'Name, email, role, and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    let student_id = null;
    if (role === 'student') {
      student_id = await generateUniqueStudentId();
    }

    const [result] = await db.query('INSERT INTO users (name, email, role, password, student_id) VALUES (?, ?, ?, ?, ?)', [name, email, role, hashedPassword, student_id]);
    res.status(201).json({ id: result.insertId, name, email, role, student_id });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Database error' });
  }
};

app.post('/api/users', async (req, res, next) => {
  const { role } = req.body;

  // If creating a non-admin user, authentication is required
  if (role !== 'admin') {
    return authenticateToken(req, res, () => handleCreateUser(req, res));
  }

  // If creating an admin, check if one already exists
  try {
    const [rows] = await db.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (rows.length > 0) {
      // An admin exists, so this action must be authenticated
      return authenticateToken(req, res, () => handleCreateUser(req, res));
    } else {
      // No admin exists, allow creating a new admin without authentication
      return handleCreateUser(req, res);
    }
  } catch (err) {
    console.error('Error checking for admin user:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});



app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' }); // User not found
    }

    const user = rows[0];

    // Check if password is null (for users created before password system)
    if (!user.password) {
        return res.status(401).json({ error: 'Invalid credentials. Please contact an admin to set your password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' }); // Passwords don't match
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, student_id: user.student_id } });

  } catch (err) {
    console.error('Error logging in user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, role } = req.body;
    if (!name || !email || !role) {
      return res.status(400).json({ error: 'Name, email, and role are required' });
    }
    const [result] = await db.query('UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?', [name, email, role, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ id: parseInt(id), name, email, role });
  } catch (err) {
    console.error(`Error updating user ${req.params.id}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE a user
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await db.query('DELETE FROM users WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(204).send(); // No content
  } catch (err) {
    console.error(`Error deleting user ${req.params.id}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- Course API Endpoints ---

// GET all courses
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM courses ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error('Error fetching courses:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST a new course
app.post('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { name, teacher_id } = req.body;
    if (!name || !teacher_id) {
      return res.status(400).json({ error: 'Name and teacher_id are required' });
    }
    const [result] = await db.query('INSERT INTO courses (name, teacher_id) VALUES (?, ?)', [name, teacher_id]);
    res.status(201).json({ id: result.insertId, name, teacher_id });
  } catch (err) {
    console.error('Error creating course:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// PUT (update) a course
app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, teacher_id } = req.body;
    if (!name || !teacher_id) {
      return res.status(400).json({ error: 'Name and teacher_id are required' });
    }
    const [result] = await db.query('UPDATE courses SET name = ?, teacher_id = ? WHERE id = ?', [name, teacher_id, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    res.json({ id: parseInt(id), name, teacher_id });
  } catch (err) {
    console.error(`Error updating course ${req.params.id}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE a course
app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await db.query('DELETE FROM courses WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }
    res.status(204).send(); // No content
  } catch (err) {
    console.error(`Error deleting course ${req.params.id}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET courses for a teacher
app.get('/api/teachers/:teacherId/courses', authenticateToken, async (req, res) => {
  try {
    const { teacherId } = req.params;
    const [rows] = await db.query('SELECT * FROM courses WHERE teacher_id = ?', [teacherId]);
    res.json(rows);
  } catch (err) {
    console.error(`Error fetching courses for teacher ${req.params.teacherId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- Enrollment API Endpoints ---

// POST to enroll a student or update enrollments for a course
app.post('/api/enrollments', authenticateToken, async (req, res) => {
  const { courseId, studentIds, course_id, student_id } = req.body;

  // Handle single student enrollment
  if (course_id && student_id) {
    try {
      // Check if the enrollment already exists
      const [existing] = await db.query('SELECT * FROM enrollments WHERE student_id = ? AND course_id = ?', [student_id, course_id]);
      if (existing.length > 0) {
        return res.status(409).json({ message: 'Student is already enrolled in this course.' });
      }

      const [result] = await db.query('INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)', [student_id, course_id]);
      return res.status(201).json({ message: 'Enrollment successful', enrollmentId: result.insertId });
    } catch (err) {
      console.error('Error enrolling student:', err);
      return res.status(500).json({ error: 'Database error' });
    }
  }

  // Handle bulk enrollment updates for a course
  if (!courseId || !studentIds || !Array.isArray(studentIds)) {
    return res.status(400).json({ error: 'courseId and a studentIds array are required for bulk updates' });
  }

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();
    await connection.query('DELETE FROM enrollments WHERE course_id = ?', [courseId]);

    if (studentIds.length > 0) {
      const values = studentIds.map(studentId => [studentId, courseId]);
      await connection.query('INSERT INTO enrollments (student_id, course_id) VALUES ?', [values]);
    }

    await connection.commit();
    res.status(201).json({ message: 'Enrollments updated successfully' });

  } catch (err) {
    await connection.rollback();
    console.error('Error updating enrollments:', err);
    res.status(500).json({ error: 'Database transaction failed' });
  } finally {
    connection.release();
  }
});

// GET courses for a student
app.get('/api/students/:studentId/courses', authenticateToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    const query = `
      SELECT 
        c.id AS course_id,
        c.name AS course_name
      FROM courses c
      JOIN enrollments e ON c.id = e.course_id
      WHERE e.student_id = ?
    `;
    const [rows] = await db.query(query, [studentId]);
    res.json({ courses: rows });
  } catch (err) {
    console.error(`Error fetching courses for student ${req.params.studentId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- Grade API Endpoints ---

// GET grades for a student by student_id (the 4-digit one)
app.get('/api/grades/student/:studentId', authenticateToken, async (req, res) => {
  try {
    const { studentId } = req.params;

    // First, find the user's internal ID from their student_id
    const [userRows] = await db.query('SELECT id, name FROM users WHERE student_id = ? AND role = \'student\'', [studentId]);

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Student not found with this ID' });
    }

    const userId = userRows[0].id;
    const studentName = userRows[0].name;

    const query = `
      SELECT 
        g.grade,
        c.name AS course_name
      FROM grades g
      JOIN courses c ON g.course_id = c.id
      WHERE g.student_id = ?
    `;
    const [rows] = await db.query(query, [userId]);

    res.json({ student_name: studentName, grades: rows });

  } catch (err) {
    console.error(`Error fetching grades for student ${req.params.studentId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET enrollments for a course
app.get('/api/enrollments/course/:courseId', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const query = `
      SELECT u.id, u.name, u.email 
      FROM users u
      JOIN enrollments e ON u.id = e.student_id
      WHERE e.course_id = ? AND u.role = 'student'
      ORDER BY u.name
    `;
    const [rows] = await db.query(query, [courseId]);
    res.json(rows);
  } catch (err) {
    console.error(`Error fetching enrollments for course ${req.params.courseId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET grades for a course
app.get('/api/grades/course/:courseId', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const [rows] = await db.query('SELECT student_id, grade FROM grades WHERE course_id = ?', [courseId]);
    res.json(rows);
  } catch (err) {
    console.error(`Error fetching grades for course ${req.params.courseId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST (add/update) grades for a course
app.post('/api/grades', authenticateToken, async (req, res) => {
  try {
    const { course_id, grades } = req.body;
    if (!course_id || !grades || !Array.isArray(grades)) {
      return res.status(400).json({ error: 'course_id and a grades array are required' });
    }

    const queries = grades.map(g => {
      if (g.student_id == null || g.grade == null) {
        // Skip invalid entries
        return null;
      }
      const query = `
        INSERT INTO grades (student_id, course_id, grade)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE grade = VALUES(grade)
      `;
      return db.query(query, [g.student_id, course_id, g.grade]);
    }).filter(q => q != null); // Filter out any null queries

    if (queries.length === 0) {
        return res.status(400).json({ error: 'No valid grades provided' });
    }

    await Promise.all(queries);

    res.status(201).json({ message: 'Grades updated successfully' });
  } catch (err) {
    console.error('Error saving grades:', err);
    res.status(500).json({ error: 'Database error while saving grades' });
  }
});

// --- Statistics API Endpoints ---

app.get('/api/statistics/students-per-course', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT c.name, COUNT(e.student_id) AS student_count
      FROM courses c
      LEFT JOIN enrollments e ON c.id = e.course_id
      GROUP BY c.id
      ORDER BY c.name
    `;
    const [rows] = await db.query(query);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching students per course statistics:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const [studentCount] = await db.query("SELECT COUNT(*) as count FROM users WHERE role = 'student'");
    const [teacherCount] = await db.query("SELECT COUNT(*) as count FROM users WHERE role = 'teacher'");
    const [courseCount] = await db.query('SELECT COUNT(*) as count FROM courses');

    res.json({
      totalStudents: studentCount[0].count,
      totalTeachers: teacherCount[0].count,
      totalCourses: courseCount[0].count,
    });
  } catch (err) {
    console.error('Error fetching analytics:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- Message API Endpoints ---

app.post('/api/messages/send', authenticateToken, async (req, res) => {
  const { recipientIds, message, subject } = req.body;
  const senderId = req.user.id; // Get sender ID from authenticated user

  if (!recipientIds || !Array.isArray(recipientIds) || recipientIds.length === 0) {
    return res.status(400).json({ message: 'Recipient IDs are required.' });
  }

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ message: 'A message is required.' });
  }
  
  if (!subject || typeof subject !== 'string') {
    return res.status(400).json({ message: 'A subject is required.' });
  }

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    // 1. Insert the message into the messages table
    const [messageResult] = await connection.query(
      'INSERT INTO messages (sender_id, subject, body) VALUES (?, ?, ?)',
      [senderId, subject, message] // Use the authenticated sender's ID
    );
    const messageId = messageResult.insertId;

    // 2. Insert into the message_recipients table
    if (recipientIds.length > 0) {
      const recipientValues = recipientIds.map(recipientId => [messageId, recipientId]);
      await connection.query('INSERT INTO message_recipients (message_id, recipient_id) VALUES ?', [recipientValues]);
    }

    await connection.commit();
    res.status(201).json({ message: 'Message sent and stored successfully.' });

  } catch (err) {
    await connection.rollback();
    console.error('Error saving message:', err);
    res.status(500).json({ error: 'Database transaction failed' });
  } finally {
    connection.release();
  }
});

app.get('/api/messages/student/:studentId', authenticateToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    const query = `
      SELECT 
        m.id,
        m.subject,
        m.body,
        m.created_at,
        u.name AS sender_name,
        mr.is_read,
        mr.id AS messageRecipientId
      FROM messages m
      JOIN message_recipients mr ON m.id = mr.message_id
      LEFT JOIN users u ON m.sender_id = u.id
      WHERE mr.recipient_id = ?
      ORDER BY m.created_at DESC
    `;
    const [rows] = await db.query(query, [studentId]);
    res.json(rows);
  } catch (err) {
    console.error(`Error fetching messages for student ${req.params.studentId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/messages/read/:messageRecipientId', authenticateToken, async (req, res) => {
  try {
    const { messageRecipientId } = req.params;
    const query = 'UPDATE message_recipients SET is_read = TRUE WHERE id = ?';
    const [result] = await db.query(query, [messageRecipientId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Message recipient not found' });
    }
    res.status(200).json({ message: 'Message marked as read' });
  } catch (err) {
    console.error(`Error marking message as read:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET unread message count for the logged-in user
app.get('/api/messages/unread-count', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = 'SELECT COUNT(*) as unreadCount FROM message_recipients WHERE recipient_id = ? AND is_read = FALSE';
    const [rows] = await db.query(query, [userId]);
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching unread message count:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET messages sent by the logged-in user
app.get('/api/messages/sent', authenticateToken, async (req, res) => {
  try {
    const senderId = req.user.id;
    const query = `
      SELECT m.id, m.subject, m.body, m.created_at, GROUP_CONCAT(u.name SEPARATOR ', ') as recipients
      FROM messages m
      JOIN message_recipients mr ON m.id = mr.message_id
      JOIN users u ON mr.recipient_id = u.id
      WHERE m.sender_id = ?
      GROUP BY m.id
      ORDER BY m.created_at DESC
    `;
    const [rows] = await db.query(query, [senderId]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching sent messages:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE a message
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    // First, find the message to check ownership
    const [messageRows] = await db.query('SELECT sender_id FROM messages WHERE id = ?', [messageId]);
    if (messageRows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const message = messageRows[0];

    // Check if the user is the sender or an admin
    if (message.sender_id !== userId && userRole !== 'admin') {
      return res.status(403).json({ error: 'You are not authorized to delete this message' });
    }

    // Delete the message
    await db.query('DELETE FROM messages WHERE id = ?', [messageId]);
    
    res.status(204).send(); // No content
  } catch (err) {
    console.error(`Error deleting message ${req.params.messageId}:`, err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
