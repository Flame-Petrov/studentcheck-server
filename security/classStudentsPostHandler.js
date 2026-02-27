const normalizeEmail = (value) => String(value || "").trim().toLowerCase();

const parsePositiveInt = (value) => {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isInteger(parsed) || parsed <= 0) return null;
    return parsed;
};

const getClassIdFromRequest = (req) => {
    const queryClassId = req?.query?.class_id;
    const bodyClassIdSnake = req?.body?.class_id;
    const bodyClassIdCamel = req?.body?.classId;
    return parsePositiveInt(queryClassId ?? bodyClassIdSnake ?? bodyClassIdCamel);
};

const extractNormalizedFaculty = (student, normalize) => {
    if (typeof student === "string" || typeof student === "number") {
        return normalize(String(student));
    }
    const value = student?.facultyNumber ?? student?.faculty_number;
    if (!value) return null;
    return normalize(String(value));
};

const resolveTeacherIdentity = async ({ req, pool, normalize, hashForLookup }) => {
    const jwtTeacherId = parsePositiveInt(req?.authTeacherId ?? req?.user?.teacherId ?? req?.user?.id);
    const jwtTeacherEmail = normalizeEmail(req?.user?.email);

    if (jwtTeacherId) {
        return { teacherId: jwtTeacherId, teacherEmail: jwtTeacherEmail || null, source: "jwt_id" };
    }

    if (jwtTeacherEmail) {
        const hash = hashForLookup(jwtTeacherEmail);
        const result = await pool.query("SELECT id FROM teachers WHERE email_hash = $1", [hash]);
        if (result.rows.length > 0) {
            return { teacherId: parsePositiveInt(result.rows[0].id), teacherEmail: jwtTeacherEmail, source: "jwt_email" };
        }
    }

    const fallbackEmailRaw =
        req?.body?.teacherEmail ??
        req?.body?.teacher_email ??
        req?.query?.teacherEmail ??
        req?.query?.teacher_email;
    const fallbackEmail = normalizeEmail(fallbackEmailRaw);
    if (!fallbackEmail) return null;

    const hash = hashForLookup(fallbackEmail);
    const result = await pool.query("SELECT id FROM teachers WHERE email_hash = $1", [hash]);
    if (!result.rows.length) return null;

    return { teacherId: parsePositiveInt(result.rows[0].id), teacherEmail: fallbackEmail, source: "fallback_email" };
};

const buildPostClassStudentsHandler = ({ pool, normalize, hashForLookup, addStudentsToClass, logger = console }) => {
    return async (req, res) => {
        const classId = getClassIdFromRequest(req);
        const students = req?.body?.students;

        if (!classId) {
            return res.status(400).send({ error: "class_id must be a valid positive integer" });
        }
        if (!Array.isArray(students) || students.length === 0) {
            return res.status(400).send({ error: "students must be a non-empty array" });
        }

        const normalizedFacultyNumbers = students
            .map((student) => extractNormalizedFaculty(student, normalize))
            .filter(Boolean);
        if (!normalizedFacultyNumbers.length) {
            return res.status(400).send({ error: "students must include facultyNumber or faculty_number" });
        }

        try {
            const teacherIdentity = await resolveTeacherIdentity({ req, pool, normalize, hashForLookup });
            if (!teacherIdentity?.teacherId) {
                return res.status(401).send({ error: "Invalid or expired token" });
            }

            const classResult = await pool.query("SELECT id, teacher_id FROM classes WHERE id = $1", [classId]);
            if (!classResult.rows.length) {
                return res.status(404).send({ error: "Class not found" });
            }

            const ownerTeacherId = parsePositiveInt(classResult.rows[0].teacher_id);
            const actorTeacherId = parsePositiveInt(teacherIdentity.teacherId);
            logger.log("[CLASS_STUDENTS_MUTATION]", {
                requestId: req.authRequestId || null,
                endpoint: "/class_students",
                classId,
                tokenTeacherId: actorTeacherId || null,
                tokenTeacherEmail: teacherIdentity.teacherEmail || null,
                resolvedOwnerTeacherId: ownerTeacherId || null,
            });

            if (!ownerTeacherId || ownerTeacherId !== actorTeacherId) {
                return res.status(403).send({ error: "You do not have permission to modify this class" });
            }

            const assignmentResult = await addStudentsToClass(classId, students);
            return res.status(200).send({
                success: true,
                classId,
                addedCount: Number(assignmentResult?.assignedCount || 0),
            });
        } catch (error) {
            logger.error("[CLASS_STUDENTS_MUTATION][DB_ERROR]", {
                requestId: req.authRequestId || null,
                endpoint: "/class_students",
                classId,
                statusCode: 500,
                code: error?.code,
            });
            return res.status(500).send({ error: "Internal server error" });
        }
    };
};

module.exports = {
    buildPostClassStudentsHandler,
    getClassIdFromRequest,
    resolveTeacherIdentity,
};
