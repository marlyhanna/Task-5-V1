import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER (hardened)
// =============================================================================
// Defense layers, outermost first:
//   1. express-mongo-sanitize (app.js) strips "$..." / "a.b" keys from input.
//   2. Joi validates the SHAPE and TYPE of every input we accept here.
//   3. Queries are built from validated values only, never from raw req.*.
//   4. Passwords are bcrypt-hashed and compared in code, not in the query.
//   5. Secret fields are select:false in the model and responses are
//      whitelisted.
// =============================================================================

// Only the fields that are safe for anyone to see.
const PUBLIC_FIELDS = 'name department role';

// What the logged-in instructor gets back about themselves. Deliberately
// excludes apiKey / privateEmail / privatePhone: the client stores this object
// in localStorage, where any XSS could read it.
function sessionProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// Escape regex metacharacters so user text is matched literally.
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// A real bcrypt hash used when the username doesn't exist, so the response
// time is the same whether or not the user exists (no username enumeration).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(128).required()
});
// Unknown keys are rejected by default (Joi's default is allowUnknown: false).

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) {
      // Generic message: don't tell attackers which rule they tripped.
      return res.status(400).json({ message: 'Invalid input' });
    }

    // Query by username ONLY (a validated string). The password never goes
    // into the query, so there is nothing for $regex/$ne to match against.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');

    const ok = await bcrypt.compare(value.password, instructor ? instructor.password : DUMMY_HASH);
    if (!instructor || !ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: sessionProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// Allow-list of searchable fields. Anything else in the query string is
// dropped (stripUnknown), so ?role=..., ?username=..., ?$where=... never reach
// the database.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(50).allow(''),
  department: Joi.string().trim().max(50).allow('')
}).options({ stripUnknown: true });

// GET /api/instructors/search?name=smith&department=math
export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query);
    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters' });
    }

    // Build the filter ourselves from validated strings.
    const filter = {};
    if (value.name) {
      // Case-insensitive "contains". The regex is built by the server from
      // escaped text, so the client can't send its own pattern.
      filter.name = new RegExp(escapeRegex(value.name), 'i');
    }
    if (value.department) {
      filter.department = value.department;
    }

    const instructors = await Instructor.find(filter)
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}