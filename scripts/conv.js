const fs = require("fs");
const path = require("path");

const inputDir = "contracts";
const outputDir = "contracts/json";

// Create output directory if it doesn't exist
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// Process each .ts file
fs.readdirSync(inputDir)
  .filter((file) => file.endsWith(".ts"))
  .forEach((file) => {
    const inputPath = path.join(inputDir, file);
    const outputPath = path.join(outputDir, file.replace(".ts", ".json"));

    // Import the TS file
    const { abi } = require(path.resolve(inputPath));

    // Write as formatted JSON
    fs.writeFileSync(outputPath, JSON.stringify(abi, null, 2));

    console.log(`Converted ${file} to ${path.basename(outputPath)}`);
  });
