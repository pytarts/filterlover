const http = require("http");

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, "http://localhost:3001");
  const target = reqUrl.searchParams.get("url");

  if (!target) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Missing url param" }));
  }

  try {
    let body = "";
    for await (const chunk of req) body += chunk;

    const options = {
      method: req.method,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      },
    };

    if (req.method === "POST") {
      options.headers["Content-Type"] = "application/json";
      if (req.headers["authorization"]) {
        options.headers["Authorization"] = req.headers["authorization"];
      }
      options.body = body;
    }

    const upstream = await fetch(target, options);
    const text = await upstream.text();
    res.writeHead(upstream.status, { "Content-Type": "application/json" });
    res.end(text);
  } catch (err) {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(3001, () => console.log("Node relay running on http://localhost:3001"));
