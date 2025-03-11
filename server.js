import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Carregar as variáveis do arquivo .env
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Conexão com MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// Rota raiz (GET /)
app.get("/", (req, res) => {
    res.send("Server is running!");
});

// Definição do Schema do Usuário
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});

const User = mongoose.model("User", UserSchema);

// Definição do Schema da Tarefa
const TaskSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    title: String,
    category: { type: String, enum: ["Today", "Upcoming", "Completed"] },
    createdAt: { type: Date, default: Date.now },
});

const Task = mongoose.model("Task", TaskSchema);

// Rota de registro de usuário
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(400).json({ error: "Email already in use" });
    }
});

// Rota de login de usuário
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
});

// Middleware de autenticação
const auth = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: "Invalid token" });
    }
};

// Rota para obter as tarefas do usuário
app.get("/tasks", auth, async (req, res) => {
    const tasks = await Task.find({ userId: req.user.userId });
    res.json(tasks);
});

// Rota para adicionar uma tarefa
app.post("/tasks", auth, async (req, res) => {
    const { title, category } = req.body;
    const task = new Task({ userId: req.user.userId, title, category });
    await task.save();
    res.status(201).json(task);
});

// Rota para deletar uma tarefa
app.delete("/tasks/:id", auth, async (req, res) => {
    await Task.findByIdAndDelete(req.params.id);
    res.json({ message: "Task deleted" });
});

// Porta do servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
