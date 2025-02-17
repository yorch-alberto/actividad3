//Acitivdad 3 Full Stack: Jorge Alberto y Erick Patricio

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs").promises;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000;
const SECRET_KEY = "mi_secreto"; // clave segura

app.use(bodyParser.json());

// cargamos tareas de json
const cargarTareas = async () => {
    try {
        const data = await fs.readFile("tareas.json", "utf8");
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
};

// guardamos tareas en json
const guardarTareas = async (tareas) => {
    await fs.writeFile("tareas.json", JSON.stringify(tareas, null, 2));
};

/*
// Middleware de autenticación
const verificarToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ mensaje: "Acceso denegado" });

    try {
        const verificado = jwt.verify(token, SECRET_KEY);
        req.usuario = verificado;
        next();
    } catch (error) {
        res.status(400).json({ mensaje: "Token inválido" });
    }
};


const verificarToken = (req, res, next) => {
    const token = req.header("Authorization");
    console.log("Token recibido:", token);  // Depuración para verificar si se recibe el token
    if (!token) return res.status(401).json({ mensaje: "Acceso denegado" });

    try {
        const verificado = jwt.verify(token, SECRET_KEY);
        req.usuario = verificado;
        next();
    } catch (error) {
        console.log("Error al verificar token:", error);  // Depuración
        res.status(400).json({ mensaje: "Token inválido" });
    }
};
*/

//verificamos el token
const verificarToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ mensaje: "Acceso denegado" });

    try {
        const verificado = jwt.verify(token.replace("Bearer ", ""), SECRET_KEY);
        req.usuario = verificado;
        next();
    } catch (error) {
        res.status(400).json({ mensaje: "Token inválido" });
    }
};


// rutas de usuarios para autenticar
app.post("/register", async (req, res) => {
    const { usuario, password } = req.body;
    if (!usuario || !password) {
        return res.status(400).json({ mensaje: "Se requiere usuario y contrasena" });
    }

    try {
        const usuarios = JSON.parse(await fs.readFile("users.json", "utf8")) || [];
        if (usuarios.find((u) => u.usuario === usuario)) {
            return res.status(400).json({ mensaje: "Ya existe este usuario" });
        }

        const hash = await bcrypt.hash(password, 10);
        usuarios.push({ usuario, password: hash });

        await fs.writeFile("users.json", JSON.stringify(usuarios, null, 2));
        res.status(201).json({ mensaje: "El usuario ha sido registrado" });
    } catch (error) {
        res.status(500).json({ mensaje: "Error en el servidor" });
    }
});

app.post("/login", async (req, res) => {
    const { usuario, password } = req.body;

    try {
        const usuarios = JSON.parse(await fs.readFile("users.json", "utf8")) || [];
        const usuarioEncontrado = usuarios.find((u) => u.usuario === usuario);
        if (!usuarioEncontrado) {
            return res.status(400).json({ mensaje: "El usuario o contraseña son incorrectos" });
        }

        const esValido = await bcrypt.compare(password, usuarioEncontrado.password);
        if (!esValido) {
            return res.status(400).json({ mensaje: "El usuario o contraseña son incorrectos" });
        }

        //expiracion del token
        const token = jwt.sign({ usuario }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ mensaje: "Error en el servidor" }); // por si algo sucede
    }
});

// rutas de tareas con autenticacion
app.get("/tareas", verificarToken, async (req, res) => {
    const tareas = await cargarTareas();
    res.json(tareas);
});

app.post("/tareas", verificarToken, async (req, res) => {
    const { titulo, descripcion } = req.body;
    if (!titulo || !descripcion) {
        return res.status(400).json({ mensaje: "Necesita un título y una descripción " });
    }

    const tareas = await cargarTareas();
    const nuevaTarea = { id: tareas.length + 1, titulo, descripcion };
    tareas.push(nuevaTarea);
    await guardarTareas(tareas);
    res.status(201).json(nuevaTarea);
});

app.put("/tareas/:id", verificarToken, async (req, res) => {
    const { id } = req.params;
    const { titulo, descripcion } = req.body;

    const tareas = await cargarTareas();
    const tarea = tareas.find((t) => t.id == id);
    if (!tarea) return res.status(404).json({ mensaje: "No se encontro la tarea" });

    tarea.titulo = titulo || tarea.titulo;
    tarea.descripcion = descripcion || tarea.descripcion;
    await guardarTareas(tareas);
    res.json(tarea);
});

app.delete("/tareas/:id", verificarToken, async (req, res) => {
    const { id } = req.params;
    let tareas = await cargarTareas();
    tareas = tareas.filter((t) => t.id != id);
    await guardarTareas(tareas);
    res.json({ mensaje: "La tarea ha sido eliminada" });
});

app.get("/", (req, res) => {
    res.send("Si ves esto funciona la app");
});


// middleware por si hay errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ mensaje: "Error interno del servidor" });
});

// iniciamos el servidor
app.listen(PORT, () => {
    console.log(`Servidor funcionando en http://localhost:${PORT}`);
});
