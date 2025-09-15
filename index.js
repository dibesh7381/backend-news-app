import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* ================== MONGODB CONNECTION ================== */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ DB Error:", err));

/* ================== MODELS ================== */
// User Schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "customer" }, // customer | reporter
  },
  { versionKey: false, collection: "newsUser" }
);
const User = mongoose.model("User", userSchema);

// Post Schema
const postSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    likes: { type: Number, default: 0 },
    dislikes: { type: Number, default: 0 },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    dislikedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    comments: {
      type: [
        {
          user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
          text: { type: String, required: true },
          createdAt: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },
  },
  { versionKey: false }
);
const Post = mongoose.model("Post", postSchema);

/* ================== MIDDLEWARE ================== */

// Auth Middleware
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, role, name, email }
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// Reporter Only Middleware
const reporterOnly = (req, res, next) => {
  if (req.user.role !== "reporter") {
    return res.status(403).json({ message: "Only reporters can access this route" });
  }
  next();
};

// Customer Only Middleware
const customerOnly = (req, res, next) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({ message: "Only customers can access this route" });
  }
  next();
};

/* ================== AUTH ROUTES ================== */
// Register
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Home Page 
app.get("/api/users/home", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


/* ================== POST ROUTES ================== */

// Get All Posts (Public)
app.get("/api/posts", async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("author", "name")
      .populate("comments.user", "name");
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get My Posts (Reporter Only)
app.get("/api/posts/my-posts", protect, reporterOnly, async (req, res) => {
  try {
    const posts = await Post.find({ author: req.user.id })
      .populate("author", "name")
      .populate("comments.user", "name");
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create Post (Reporter Only)
app.post("/api/posts", protect, reporterOnly, async (req, res) => {
  try {
    const { title, description } = req.body;
    const post = await Post.create({ title, description, author: req.user.id });
    res.status(201).json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Update Post (Reporter Only)
app.put("/api/posts/:id", protect, reporterOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: "Post not found" });
    if (post.author.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    post.title = req.body.title || post.title;
    post.description = req.body.description || post.description;
    await post.save();

    res.json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Delete Post (Reporter Only)
app.delete("/api/posts/:id", protect, reporterOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: "Post not found" });
    if (post.author.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    await post.deleteOne();
    res.json({ message: "Post deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== COMMENT ROUTES (Customer Only) ================== */

// Add comment
app.post("/api/posts/:id/comments", protect, customerOnly, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ message: "Comment text required" });

    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    post.comments.push({ user: req.user.id, text });
    await post.save();
    await post.populate("comments.user", "name");
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Edit comment
app.put("/api/posts/:postId/comments/:commentId", protect, customerOnly, async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.postId).populate("comments.user", "name");
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comment = post.comments.id(req.params.commentId);
    if (!comment) return res.status(404).json({ message: "Comment not found" });
    if (comment.user._id.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    comment.text = text;
    await post.save();
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Delete comment
app.delete("/api/posts/:postId/comments/:commentId", protect, customerOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId).populate("comments.user", "name");
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comment = post.comments.id(req.params.commentId);
    if (!comment) return res.status(404).json({ message: "Comment not found" });
    if (comment.user._id.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    comment.deleteOne();
    await post.save();
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== LIKE / DISLIKE (Customer Only) ================== */
app.post("/api/posts/:id/like", protect, customerOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    const userId = req.user.id;

    if (post.likedBy.includes(userId)) {
      post.likes -= 1;
      post.likedBy.pull(userId);
    } else {
      post.likes += 1;
      post.likedBy.push(userId);

      if (post.dislikedBy.includes(userId)) {
        post.dislikes -= 1;
        post.dislikedBy.pull(userId);
      }
    }

    await post.save();
    res.json({ likes: post.likes, dislikes: post.dislikes });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/posts/:id/dislike", protect, customerOnly, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    const userId = req.user.id;

    if (post.dislikedBy.includes(userId)) {
      post.dislikes -= 1;
      post.dislikedBy.pull(userId);
    } else {
      post.dislikes += 1;
      post.dislikedBy.push(userId);

      if (post.likedBy.includes(userId)) {
        post.likes -= 1;
        post.likedBy.pull(userId);
      }
    }

    await post.save();
    res.json({ likes: post.likes, dislikes: post.dislikes });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== CREATE TEST REPORTER ================== */
app.get("/api/add-reporter", async (req, res) => {
  try {
    const reporterEmail = "dibesh@example.com";
    const existingReporter = await User.findOne({ email: reporterEmail });
    if (existingReporter)
      return res.json({ message: "Reporter already exists", reporter: existingReporter });

    const hashedPassword = await bcrypt.hash("dibesh1234", 10);
    const reporter = await User.create({
      name: "Dibesh",
      email: reporterEmail,
      password: hashedPassword,
      role: "reporter",
    });

    res.status(201).json({ message: "Reporter created successfully", reporter });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== PROFILE ================== */
app.get("/api/users/profile", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== START SERVER ================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
