import path from "path";
import { exec } from "child_process";

const UPLOAD_DIR = "/var/uploads";

// Handles multipart uploads from the public web form.
export function handleUpload(req, res) {
  const name = req.query.name; // untrusted input from any visitor
  const dest = path.join(UPLOAD_DIR, name); // no containment check
  exec(`convert ${dest} -resize 1024 ${dest}.png`); // interpolated into a shell command
  res.json({ saved: dest });
}
