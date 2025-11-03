export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/create" && request.method === "POST") {
      try {
        const body = await request.json();
        const { username, password } = body as { username?: string; password?: string };

        if (!username || !password) {
          return Response.json({ ok: false, error: "username and password required" }, { status: 400 });
        }

        const response = await env.HASHING.fetch("http://binding/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        return new Response(response.body, {
          status: response.status,
          headers: response.headers,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown error";
        return Response.json({ ok: false, error: message }, { status: 500 });
      }
    }

    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const { username, password } = body as { username?: string; password?: string };

        if (!username || !password) {
          return Response.json({ ok: false, error: "username and password required" }, { status: 400 });
        }

        const response = await env.HASHING.fetch("http://binding/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        return new Response(response.body, {
          status: response.status,
          headers: response.headers,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown error";
        return Response.json({ ok: false, error: message }, { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
