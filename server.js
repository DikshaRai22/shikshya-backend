// server.js
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Cloudinary for persistent image storage
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();
const PORT = process.env.PORT || 3000;

// ========== ENVIRONMENT VARIABLES ==========
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "shikshya2025";
const FRONTEND_URL = process.env.FRONTEND_URL || "*";
const JWT_SECRET = process.env.JWT_SECRET || "shikshya_secret_2025";

// Cloudinary config (if available)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ========== SECURITY MIDDLEWARE ==========
// ========== SECURITY MIDDLEWARE ==========
// Configure Helmet to allow inline scripts (for admin.html)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https:",
          "fonts.googleapis.com",
        ],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https:",
          "cdnjs.cloudflare.com",
        ],
        fontSrc: ["'self'", "https:", "data:"],
        imgSrc: ["'self'", "data:", "https:", "http://localhost:3000"],
       connectSrc: [
 "'self'",
 "http://localhost:3000",
 "https://selfless-caring-production.up.railway.app"
],
      },
    },
  }),
);

// ========== CORS CONFIGURATION ==========
const allowedOrigins = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://localhost:3000",
  "https://yourfrontend.vercel.app",
  "https://yourdomain.com"
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS blocked"));
    }
  },
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","x-admin-token","Authorization"],
  credentials: true
}));

app.options("*", cors());

// ========== BODY PARSERS ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend files (admin.html, index.html, css, js)
app.use(express.static(__dirname));

// ========== RATE LIMITING ==========
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many product uploads. Please wait a moment." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

// ========== CHECK CLOUDINARY CONFIGURATION ==========
const isCloudinaryConfigured =
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY &&
  process.env.CLOUDINARY_API_SECRET;

// ========== MULTER STORAGE (Cloudinary or Local) ==========
let upload;

if (isCloudinaryConfigured) {
  console.log(
    "☁️  Cloudinary configured - images will be stored permanently on CDN",
  );

  const cloudinaryStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: "shikshya-products",
      allowed_formats: ["jpg", "jpeg", "png", "webp"],
      transformation: [
        { width: 800, height: 1000, crop: "limit" },
        { quality: "auto", fetch_format: "auto" },
      ],
      public_id: (req, file) =>
        "product-" + Date.now() + "-" + Math.round(Math.random() * 1000),
    },
  });

  upload = multer({
    storage: cloudinaryStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const allowedTypes = /jpeg|jpg|png|gif|webp/;
      const extname = allowedTypes.test(
        path.extname(file.originalname).toLowerCase(),
      );
      const mimetype = allowedTypes.test(file.mimetype);
      if (mimetype && extname) return cb(null, true);
      cb(new Error("Only image files are allowed"));
    },
  });
} else {
  console.log(
    "⚠️  Cloudinary not configured - using local file storage (will not persist on Railway/Render)",
  );
  console.log(
    "   To enable permanent image storage, add Cloudinary credentials to .env",
  );

  const uploadDir = path.join(__dirname, "uploads");
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

  const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const basename = path.basename(file.originalname, ext);
      const sanitizedName = basename
        .replace(/[^a-zA-Z0-9]/g, "-")
        .toLowerCase();
      cb(null, `${sanitizedName}-${Date.now()}${ext || ".jpg"}`);
    },
  });

  upload = multer({
    storage: diskStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const allowedTypes = /jpeg|jpg|png|gif|webp/;
      const extname = allowedTypes.test(
        path.extname(file.originalname).toLowerCase(),
      );
      const mimetype = allowedTypes.test(file.mimetype);
      if (mimetype && extname) return cb(null, true);
      cb(new Error("Only image files are allowed"));
    },
  });

  // Serve static files from uploads folder (local only)
  app.use("/uploads", express.static(path.join(__dirname, "uploads")));
}

// ========== HELPER: Extract public_id from Cloudinary URL ==========
function getPublicIdFromUrl(url) {
  if (!url || !url.includes("cloudinary")) return null;
  try {
    const parts = url.split("/");
    const filename = parts[parts.length - 1].split(".")[0];
    const folder = parts[parts.length - 2];
    return `${folder}/${filename}`;
  } catch (e) {
    return null;
  }
}

// ========== DATABASE SETUP ==========
const DB_PATH = path.join(__dirname, "db.json");

const initializeDatabase = () => {
  if (!fs.existsSync(DB_PATH)) {
    const sampleProducts = [
      {
        id: 1,
        name: "Traditional Nepali Doko Bag",
        price: 2500,
        originalPrice: 3000,
        category: "Traditional",
        description: "Handwoven bamboo bag used by farmers in Nepal.",
        imageUrl: null,
        stock: 15,
        badge: "Best Seller",
        rating: 4.8,
        createdAt: new Date().toISOString(),
      },
      {
        id: 2,
        name: "Hemp Organic Tote",
        price: 1800,
        originalPrice: 2200,
        category: "Eco-friendly",
        description: "Durable hemp fiber tote bag, handcrafted in Kathmandu.",
        imageUrl: null,
        stock: 25,
        badge: "New Arrival",
        rating: 4.5,
        createdAt: new Date().toISOString(),
      },
      {
        id: 3,
        name: "Pashmina Wool Clutch",
        price: 3500,
        originalPrice: 4500,
        category: "Premium",
        description:
          "Luxurious pashmina wool clutch with traditional Nepali patterns.",
        imageUrl: null,
        stock: 8,
        badge: "Limited Stock",
        rating: 4.9,
        createdAt: new Date().toISOString(),
      },
      {
        id: 4,
        name: "Khukuri Backpack",
        price: 4200,
        originalPrice: 5000,
        category: "Adventure",
        description: "Rugged backpack inspired by the famous Khukuri knife.",
        imageUrl: null,
        stock: 12,
        badge: "",
        rating: 4.7,
        createdAt: new Date().toISOString(),
      },
      {
        id: 5,
        name: "Everest Trek Daypack",
        price: 3200,
        originalPrice: 3800,
        category: "Adventure",
        description: "Lightweight daypack perfect for Everest Base Camp treks.",
        imageUrl: null,
        stock: 20,
        badge: "Best Seller",
        rating: 4.6,
        createdAt: new Date().toISOString(),
      },
      {
        id: 6,
        name: "Mandala Print Canvas Bag",
        price: 1500,
        originalPrice: 1800,
        category: "Casual",
        description: "Colorful canvas bag with mandala prints.",
        imageUrl: null,
        stock: 30,
        badge: "",
        rating: 4.4,
        createdAt: new Date().toISOString(),
      },
    ];

    const sampleOrders = [
      {
        id: uuidv4(),
        orderNumber: "SKY-1001",
        customerName: "Ramesh Adhikari",
        phone: "9812345678",
        address: "Thamel, Kathmandu",
        items: [
          {
            productId: 1,
            productName: "Traditional Nepali Doko Bag",
            price: 2500,
            quantity: 1,
            itemTotal: 2500,
            image: null,
          },
        ],
        subtotal: 2500,
        shippingCharge: 0,
        total: 2500,
        paymentMethod: "COD",
        status: "Delivered",
        whatsappSent: true,
        note: "",
        createdAt: new Date().toISOString(),
      },
    ];

    const initialData = {
      products: sampleProducts,
      categories: [
        "Traditional",
        "Eco-friendly",
        "Premium",
        "Adventure",
        "Casual",
      ],
      orders: sampleOrders,
      users: [],
      reviews: [],
    };

    fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 2));
    console.log("✅ Database initialized with sample products");
  }
};

const readDB = () => JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
const writeDB = (data) =>
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

initializeDatabase();

// ========== STOCK HELPERS ==========
function validateCartItems(items) {
  const errors = [];
  const db = readDB();
  for (const item of items) {
    const productId =
      typeof item.productId === "string"
        ? parseInt(item.productId)
        : item.productId;
    const product = db.products.find((p) => p.id === productId);
    if (!product) errors.push(`Product "${item.productName}" not found`);
    else if (product.stock < item.quantity)
      errors.push(
        `Only ${product.stock} units of "${product.name}" available.`,
      );
  }
  return errors;
}

function updateProductStock(items, operation) {
  const db = readDB();
  for (const item of items) {
    const productId =
      typeof item.productId === "string"
        ? parseInt(item.productId)
        : item.productId;
    const idx = db.products.findIndex((p) => p.id === productId);
    if (idx !== -1) {
      if (operation === "decrease") db.products[idx].stock -= item.quantity;
      else if (operation === "increase")
        db.products[idx].stock += item.quantity;
    }
  }
  writeDB(db);
}

// ========== AUTH MIDDLEWARE ==========
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Login required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const optionalAuthMiddleware = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch (e) {}
  }
  next();
};

const adminAuth = (req, res, next) => {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role || "customer",
    },
    JWT_SECRET,
    { expiresIn: "7d" },
  );
}

// ========== HEALTH CHECK ==========
app.get("/health", (req, res) => {
  const db = readDB();
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    products: db.products.length,
  });
});

// ========== PUBLIC ROUTES ==========
app.get("/api/products", (req, res) => {
  const db = readDB();
  let products = db.products;
  const { category, search } = req.query;
  if (category && category !== "all")
    products = products.filter((p) => p.category === category);
  if (search)
    products = products.filter((p) =>
      p.name.toLowerCase().includes(search.toLowerCase()),
    );
  res.json({ success: true, count: products.length, products });
});

app.get("/api/products/:id", (req, res) => {
  const db = readDB();
  const product = db.products.find((p) => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ error: "Product not found" });
  res.json({ success: true, product });
});

app.get("/api/categories", (req, res) => {
  const db = readDB();
  res.json({ success: true, categories: db.categories });
});

app.get("/api/orders", (req, res) => {
  const db = readDB();
  let orders = db.orders || [];
  const { status } = req.query;
  if (status) orders = orders.filter((o) => o.status === status);
  orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, count: orders.length, orders });
});

app.get("/api/orders/:id", (req, res) => {
  const db = readDB();
  const order = db.orders.find((o) => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  res.json({ success: true, order });
});

app.get("/api/stats", (req, res) => {
  const db = readDB();
  const products = db.products || [];
  const orders = db.orders || [];
  const totalRevenue = orders
    .filter((o) => o.status !== "Cancelled")
    .reduce((sum, o) => sum + o.total, 0);
  const lowStock = products
    .filter((p) => p.stock < 5)
    .map((p) => ({ id: p.id, name: p.name, stock: p.stock }));
  const recentOrders = [...orders]
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 5);
  res.json({
    success: true,
    stats: {
      totalProducts: products.length,
      totalOrders: orders.length,
      totalRevenue,
      pendingOrders: orders.filter((o) => o.status === "Pending").length,
      lowStock,
      recentOrders,
    },
  });
});

// ========== AUTH ROUTES ==========
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const db = readDB();
    if (!name || name.length < 2)
      return res
        .status(400)
        .json({ error: "Name must be at least 2 characters" });
    if (!email || !/^\S+@\S+\.\S+$/.test(email))
      return res.status(400).json({ error: "Valid email required" });
    if (!password || password.length < 8)
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });

    if (db.users?.find((u) => u.email === email))
      return res.status(409).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      name: name.trim(),
      email,
      password: hashedPassword,
      googleId: null,
      avatar: null,
      phone: "",
      address: "",
      wishlist: [],
      role: "customer",
      createdAt: new Date().toISOString(),
    };

    if (!db.users) db.users = [];
    db.users.push(newUser);
    writeDB(db);

    const token = generateToken(newUser);
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({ success: true, token, user: userWithoutPassword });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = readDB();
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = db.users?.find((u) => u.email === email);
    if (!user)
      return res.status(401).json({ error: "No account with this email" });

    if (user.googleId && !user.password)
      return res.status(401).json({ error: "This email uses Google login" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Incorrect password" });

    const token = generateToken(user);
    const { password: _, ...userWithoutPassword } = user;
    res.json({ success: true, token, user: userWithoutPassword });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const user = db.users?.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    const { password, ...userWithoutPassword } = user;
    res.json({ success: true, user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

app.put("/api/auth/profile", authMiddleware, (req, res) => {
  try {
    const { name, phone, address } = req.body;
    const db = readDB();
    const userIndex = db.users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1)
      return res.status(404).json({ error: "User not found" });
    if (name) db.users[userIndex].name = name.trim();
    if (phone !== undefined) db.users[userIndex].phone = phone;
    if (address !== undefined) db.users[userIndex].address = address;
    writeDB(db);
    const { password, ...userWithoutPassword } = db.users[userIndex];
    res.json({ success: true, user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ error: "Failed to update profile" });
  }
});

app.get("/api/wishlist", authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const user = db.users.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    const wishlistProducts = db.products.filter((p) =>
      user.wishlist.includes(p.id.toString()),
    );
    res.json({ success: true, wishlist: wishlistProducts });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch wishlist" });
  }
});

app.post("/api/wishlist/:productId", authMiddleware, (req, res) => {
  try {
    const { productId } = req.params;
    const db = readDB();
    const userIndex = db.users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1)
      return res.status(404).json({ error: "User not found" });
    const user = db.users[userIndex];
    const isInWishlist = user.wishlist.includes(productId);
    if (isInWishlist)
      user.wishlist = user.wishlist.filter((id) => id !== productId);
    else user.wishlist.push(productId);
    writeDB(db);
    res.json({ success: true, wishlist: user.wishlist, added: !isInWishlist });
  } catch (error) {
    res.status(500).json({ error: "Failed to update wishlist" });
  }
});

app.get("/api/my-orders", authMiddleware, (req, res) => {
  try {
    const db = readDB();
    const userOrders = db.orders.filter((o) => o.userId === req.user.id);
    userOrders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ success: true, count: userOrders.length, orders: userOrders });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

// ========== PROTECTED ADMIN ROUTES ==========
app.post(
  "/api/products",
  uploadLimiter,
  adminAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      const db = readDB();
      const {
        name,
        price,
        category,
        description,
        stock,
        originalPrice,
        badge,
        rating,
      } = req.body;
      if (!name || !price || !category)
        return res.status(400).json({ error: "Missing required fields" });

      const newId =
        db.products.length > 0
          ? Math.max(...db.products.map((p) => p.id)) + 1
          : 1;
     let imageUrl = null;

if (req.file) {
  imageUrl = isCloudinaryConfigured
    ? req.file.path
    : `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
}

      const newProduct = {
        id: newId,
        name: name.trim(),
        price: parseFloat(price),
        originalPrice: originalPrice ? parseFloat(originalPrice) : null,
        category: category.trim(),
        description: description ? description.trim() : "",
        imageUrl: imageUrl,
        stock: stock ? parseInt(stock) : 0,
        badge: badge || "",
        rating: rating ? parseFloat(rating) : null,
        createdAt: new Date().toISOString(),
      };

      if (!db.categories.includes(category)) db.categories.push(category);
      db.products.push(newProduct);
      writeDB(db);
      res.status(201).json({
        success: true,
        message: "Product created",
        product: newProduct,
      });
    } catch (error) {
      console.error("Error creating product:", error);
      res.status(500).json({ error: "Failed to create product" });
    }
  },
);

app.put(
  "/api/products/:id",
  adminAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      const db = readDB();
      const productId = parseInt(req.params.id);
      const idx = db.products.findIndex((p) => p.id === productId);
      if (idx === -1)
        return res.status(404).json({ error: "Product not found" });

      const existing = db.products[idx];
      const {
        name,
        price,
        category,
        description,
        stock,
        originalPrice,
        badge,
        rating,
      } = req.body;

      let imageUrl = existing.imageUrl;
      if (req.file) {
        if (existing.imageUrl && isCloudinaryConfigured) {
          const publicId = getPublicIdFromUrl(existing.imageUrl);
          if (publicId)
            await cloudinary.uploader
              .destroy(publicId)
              .catch((e) => console.log("Delete failed:", e));
        }
       imageUrl = isCloudinaryConfigured
  ? req.file.path
  : `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
      }

      db.products[idx] = {
        ...existing,
        name: name ? name.trim() : existing.name,
        price: price ? parseFloat(price) : existing.price,
        originalPrice:
          originalPrice !== undefined
            ? originalPrice
              ? parseFloat(originalPrice)
              : null
            : existing.originalPrice,
        category: category ? category.trim() : existing.category,
        description: description ? description.trim() : existing.description,
        stock: stock !== undefined ? parseInt(stock) : existing.stock,
        badge: badge !== undefined ? badge : existing.badge,
        rating:
          rating !== undefined
            ? rating
              ? parseFloat(rating)
              : null
            : existing.rating,
        imageUrl: imageUrl,
        updatedAt: new Date().toISOString(),
      };

      if (category && !db.categories.includes(category))
        db.categories.push(category);
      writeDB(db);
      res.json({
        success: true,
        message: "Product updated",
        product: db.products[idx],
      });
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ error: "Failed to update product" });
    }
  },
);

app.delete("/api/products/:id", adminAuth, async (req, res) => {
  try {
    const db = readDB();
    const productId = parseInt(req.params.id);
    const idx = db.products.findIndex((p) => p.id === productId);
    if (idx === -1) return res.status(404).json({ error: "Product not found" });

    const product = db.products[idx];
    if (product.imageUrl && isCloudinaryConfigured) {
      const publicId = getPublicIdFromUrl(product.imageUrl);
      if (publicId)
        await cloudinary.uploader
          .destroy(publicId)
          .catch((e) => console.log("Delete failed:", e));
    } else if (product.imageUrl && !isCloudinaryConfigured) {
      const localPath = path.join(__dirname, product.imageUrl);
      if (fs.existsSync(localPath)) fs.unlinkSync(localPath);
    }

    db.products.splice(idx, 1);
    writeDB(db);
    res.json({ success: true, message: "Product deleted" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

app.post("/api/categories", adminAuth, (req, res) => {
  const db = readDB();
  const { name } = req.body;
  if (!name || name.trim() === "")
    return res.status(400).json({ error: "Category name required" });
  if (db.categories.includes(name.trim()))
    return res.status(409).json({ error: "Category exists" });
  db.categories.push(name.trim());
  writeDB(db);
  res.json({ success: true, categories: db.categories });
});

app.post("/api/upload", adminAuth, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  res.json({
  success: true,
  imageUrl: isCloudinaryConfigured
    ? req.file.path
    : `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`
});
});

app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD)
    return res.json({
      success: true,
      token: ADMIN_PASSWORD,
      message: "Welcome, Admin!",
    });
  return res.status(401).json({ error: "Wrong admin password" });
});

// ========== ORDER ROUTE ==========
app.post("/api/orders", optionalAuthMiddleware, (req, res) => {
  try {
    const { customerName, phone, address, note, items, paymentMethod } =
      req.body;
    if (!customerName || !phone || !/^\d{10}$/.test(phone) || !address)
      return res.status(400).json({ error: "Missing required fields" });
    if (!items || items.length === 0)
      return res.status(400).json({ error: "No items" });

    const stockErrors = validateCartItems(items);
    if (stockErrors.length > 0)
      return res
        .status(409)
        .json({ error: "Stock issues", details: stockErrors });

    const db = readDB();
    let subtotal = 0;
    const processedItems = items.map((item) => {
      const itemTotal = item.price * item.quantity;
      subtotal += itemTotal;
      return {
        productId: parseInt(item.productId),
        productName: item.productName,
        price: item.price,
        quantity: item.quantity,
        itemTotal,
        image: item.image,
      };
    });

    const shipping = subtotal >= 2000 ? 0 : 120;
    const newOrder = {
      id: uuidv4(),
      orderNumber: `SKY-${1001 + db.orders.length}`,
      customerName: customerName.trim(),
      phone,
      address: address.trim(),
      items: processedItems,
      subtotal,
      shippingCharge: shipping,
      total: subtotal + shipping,
      paymentMethod,
      status: "Pending",
      whatsappSent: true,
      note: note || "",
      createdAt: new Date().toISOString(),
      userId: req.user?.id || null,
    };

    updateProductStock(items, "decrease");
    db.orders.push(newOrder);
    writeDB(db);
    res.status(201).json({ success: true, order: newOrder });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Order failed" });
  }
});

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "FILE_TOO_LARGE")
      return res.status(400).json({ error: "File too large (max 5MB)" });
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.use((req, res) => res.status(404).json({ error: "Route not found" }));

// ========== GRACEFUL SHUTDOWN ==========
process.on("SIGTERM", () => {
  console.log("Shutting down...");
  process.exit(0);
});
process.on("SIGINT", () => {
  console.log("Shutting down...");
  process.exit(0);
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log(`\n🚀 Shikshya API Server`);
  console.log(`📡 http://localhost:${PORT}`);
  console.log(
    `🖼️  Image storage: ${isCloudinaryConfigured ? "☁️ Cloudinary CDN (persistent)" : "💾 Local filesystem (will reset on deploy)"}`,
  );
  console.log(
    `🔐 Admin password: ${ADMIN_PASSWORD === "shikshya2025" ? "⚠️ default" : "✅ configured"}\n`,
  );
});

module.exports = app;
