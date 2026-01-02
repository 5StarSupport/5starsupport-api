const { getStore } = require("@netlify/blobs");

exports.config = {
  name: "bootstrap-blobs"
};

exports.handler = async () => {
  const store = getStore("5starsupport-crm");

  await store.set(
    "initialized",
    {
      createdAt: new Date().toISOString(),
      ok: true
    },
    { type: "json" }
  );

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "Blob store initialized" })
  };
};
