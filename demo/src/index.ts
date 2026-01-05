import { Hono } from "hono";
import { HomePage } from "./page";
import { createUser, verifyUser } from "./handlers";

const app = new Hono<{ Bindings: Env }>();

app.get("/", (c) => c.html(HomePage()));
app.post("/create", createUser);
app.post("/verify", verifyUser);

export default app;
