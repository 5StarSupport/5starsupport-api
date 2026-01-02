// File: netlify/functions/bootstrap-blobs.js
const { getDataStore, json } = require("./_utils");

exports.handler = async (event) => {
  try {
    const store = getDataStore(event);

    // Force-create the store by writing a key
    await store.set("leads:index", [], { type: "json" });

    return json(200, {
      success: true,
      message: "Blob store initialized",
    });
  } catch (err) {
    return json(500, {
      error: true,
      message: err.message,
    });
  }
};
