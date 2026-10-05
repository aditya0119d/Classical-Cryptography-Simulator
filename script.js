"use strict";

/*
 * Classical Cryptography Simulator
 * All cryptographic processing happens locally in the browser.
 */

/* =========================================================
   APPLICATION STATE
========================================================= */

const state = {
    algorithm: "caesar",
    operation: "encrypt"
};

const algorithmData = {
    caesar: {
        name: "Caesar Cipher",
        description: "Shifts each alphabetic character by a fixed number.",
        key: "Integer shift value",
        example: "HELLO + 3 → KHOOR",
        requirements: "Letters preserve their case. Spaces and punctuation remain unchanged.",
        placeholder: "Enter shift value (e.g. 3)",
        help: "Caesar key must be an integer."
    },

    vigenere: {
        name: "Vigenère Cipher",
        description: "Uses a repeating keyword as a sequence of Caesar shifts.",
        key: "Alphabetic keyword",
        example: "ATTACKATDAWN + LEMON → LXFOPVEFRNHR",
        requirements: "The keyword advances only when a letter is processed.",
        placeholder: "Enter keyword (e.g. SECRET)",
        help: "Use letters A-Z only."
    },

    playfair: {
        name: "Playfair Cipher",
        description: "Encrypts pairs of letters using a 5×5 key square.",
        key: "Alphabetic keyword",
        example: "Key: MONARCHY",
        requirements: "I and J share one cell. X is used for padding.",
        placeholder: "Enter keyword (e.g. MONARCHY)",
        help: "Use letters A-Z only. J is merged with I."
    },

    hill: {
        name: "Hill Cipher",
        description: "Uses matrix multiplication modulo 26.",
        key: "Comma-separated matrix values",
        example: "3,3,2,5 → 2×2 matrix",
        requirements: "Only 2×2, 3×3 and 4×4 matrices are supported.",
        placeholder: "Enter matrix key (e.g. 3,3,2,5)",
        help: "Example 2×2 key: 3,3,2,5"
    },

    otp: {
        name: "One-Time Pad",
        description: "Uses a key with the same number of letters as the message.",
        key: "Random alphabetic key",
        example: "HELLO + XMCKL",
        requirements: "Key must have exactly the same number of letters and must not be reused.",
        placeholder: "Enter key with same length as text",
        help: "Key length must match the number of message letters."
    },

    railfence: {
        name: "Rail Fence Cipher",
        description: "Rearranges characters using a zig-zag pattern.",
        key: "Number of rails",
        example: "WEAREDISCOVEREDFLEEATONCE + 3 rails",
        requirements: "Rails must be an integer of at least 2.",
        placeholder: "Enter number of rails (e.g. 3)",
        help: "Use 2 or more rails."
    }
};

/* =========================================================
   DOM REFERENCES
========================================================= */

const messageInput = document.getElementById("message");
const keyInput = document.getElementById("key");
const keyHelp = document.getElementById("key-help");
const errorMessage = document.getElementById("error-message");

const algorithmCards = document.querySelectorAll(".algorithm-card");

const encryptBtn = document.getElementById("encrypt-btn");
const decryptBtn = document.getElementById("decrypt-btn");

const convertBtn = document.getElementById("convert-btn");
const exampleBtn = document.getElementById("example-btn");

const resultSection = document.getElementById("result-section");
const explanationSection = document.getElementById("explanation-section");

const resultAlgorithm = document.getElementById("result-algorithm");
const resultOperation = document.getElementById("result-operation");
const resultKey = document.getElementById("result-key");
const resultInput = document.getElementById("result-input");
const resultOutput = document.getElementById("result-output");

const copyBtn = document.getElementById("copy-btn");
const clearBtn = document.getElementById("clear-btn");
const copyStatus = document.getElementById("copy-status");

const formulaElement = document.getElementById("formula");
const stepsList = document.getElementById("steps-list");
const visualization = document.getElementById("visualization");

const infoText = document.getElementById("info-text");
const infoKey = document.getElementById("info-key");
const infoExample = document.getElementById("info-example");
const infoRequirements = document.getElementById("info-requirements");

/* =========================================================
   GENERAL HELPERS
========================================================= */

function mod(value, modulus) {
    return ((value % modulus) + modulus) % modulus;
}

function charToNumber(char) {
    return char.toUpperCase().charCodeAt(0) - 65;
}

function numberToChar(number) {
    return String.fromCharCode(65 + mod(number, 26));
}

function isLetter(char) {
    return /^[A-Za-z]$/.test(char);
}

function setError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.toggle("show", Boolean(message));
}

function clearError() {
    setError("");
}

function updateAlgorithmInfo() {
    const data = algorithmData[state.algorithm];

    keyInput.placeholder = data.placeholder;
    keyHelp.textContent = data.help;

    infoText.textContent = data.description;
    infoKey.textContent = data.key;
    infoExample.textContent = data.example;
    infoRequirements.textContent = data.requirements;
}

function hideResults() {
    resultSection.classList.add("hidden");
    explanationSection.classList.add("hidden");
}

function getLetters(text) {
    return text.match(/[A-Za-z]/g) || [];
}

function preserveCase(original, replacement) {
    return original === original.toLowerCase()
        ? replacement.toLowerCase()
        : replacement.toUpperCase();
}

/* =========================================================
   CAESAR CIPHER
========================================================= */

function caesarCipher(text, key, decrypt) {
    const shift = Number(key);

    if (!Number.isInteger(shift)) {
        throw new Error("Caesar key must be an integer.");
    }

    const actualShift = decrypt ? -shift : shift;
    const steps = [];
    let output = "";

    for (const char of text) {
        if (!isLetter(char)) {
            output += char;
            continue;
        }

        const originalValue = charToNumber(char);
        const resultValue = mod(originalValue + actualShift, 26);
        const resultChar = numberToChar(resultValue);

        output += preserveCase(char, resultChar);

        if (steps.length < 12) {
            steps.push(
                `${char} (${originalValue}) ${decrypt ? "-" : "+"} ` +
                `${Math.abs(shift)} mod 26 = ${resultValue} → ${resultChar}`
            );
        }
    }

    return {
        output,
        formula: decrypt
            ? "P = (C − K) mod 26"
            : "C = (P + K) mod 26",
        steps
    };
}

/* =========================================================
   VIGENERE CIPHER
========================================================= */

function vigenereCipher(text, key, decrypt) {
    const cleanKey = key.replace(/[^A-Za-z]/g, "").toUpperCase();

    if (!cleanKey) {
        throw new Error("Vigenère key must contain alphabetic characters.");
    }

    if (cleanKey.length !== key.length) {
        throw new Error("Vigenère key must contain letters A-Z only.");
    }

    let keyIndex = 0;
    let output = "";
    const steps = [];

    for (const char of text) {
        if (!isLetter(char)) {
            output += char;
            continue;
        }

        const p = charToNumber(char);
        const kChar = cleanKey[keyIndex % cleanKey.length];
        const k = charToNumber(kChar);

        const result = decrypt
            ? mod(p - k, 26)
            : mod(p + k, 26);

        const resultChar = numberToChar(result);

        output += preserveCase(char, resultChar);

        if (steps.length < 12) {
            steps.push(
                `${char} (${p}) ${decrypt ? "-" : "+"} ${kChar} (${k}) mod 26 = ${result} → ${resultChar}`
            );
        }

        keyIndex++;
    }

    return {
        output,
        formula: decrypt
            ? "Pᵢ = (Cᵢ − Kᵢ) mod 26"
            : "Cᵢ = (Pᵢ + Kᵢ) mod 26",
        steps
    };
}

/* =========================================================
   PLAYFAIR HELPERS
========================================================= */

function preparePlayfairKey(key) {
    const clean = key
        .toUpperCase()
        .replace(/J/g, "I")
        .replace(/[^A-Z]/g, "");

    if (!clean) {
        throw new Error("Playfair key must contain alphabetic characters.");
    }

    let result = "";

    for (const char of clean) {
        if (!result.includes(char)) {
            result += char;
        }
    }

    const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

    for (const char of alphabet) {
        if (!result.includes(char)) {
            result += char;
        }
    }

    return result;
}

function createPlayfairGrid(key) {
    const prepared = preparePlayfairKey(key);
    const grid = [];

    for (let i = 0; i < 25; i += 5) {
        grid.push(prepared.slice(i, i + 5).split(""));
    }

    return grid;
}

function findPlayfairPosition(grid, char) {
    const target = char === "J" ? "I" : char;

    for (let row = 0; row < 5; row++) {
        for (let col = 0; col < 5; col++) {
            if (grid[row][col] === target) {
                return { row, col };
            }
        }
    }

    return null;
}

function preparePlayfairPairs(text, decrypt) {
    let clean = text.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");

    if (decrypt) {
        if (clean.length % 2 !== 0) {
            throw new Error("Playfair ciphertext must contain an even number of letters.");
        }

        const pairs = [];

        for (let i = 0; i < clean.length; i += 2) {
            pairs.push(clean.slice(i, i + 2));
        }

        return pairs;
    }

    const pairs = [];

    let i = 0;

    while (i < clean.length) {
        const first = clean[i];
        const second = clean[i + 1];

        if (!second) {
            pairs.push(first + "X");
            i++;
        } else if (first === second) {
            pairs.push(first + "X");
            i++;
        } else {
            pairs.push(first + second);
            i += 2;
        }
    }

    return pairs;
}

/* =========================================================
   PLAYFAIR CIPHER
========================================================= */

function playfairCipher(text, key, decrypt) {
    const grid = createPlayfairGrid(key);
    const pairs = preparePlayfairPairs(text, decrypt);

    let output = "";
    const steps = [];

    for (const pair of pairs) {
        const a = findPlayfairPosition(grid, pair[0]);
        const b = findPlayfairPosition(grid, pair[1]);

        if (!a || !b) {
            throw new Error("Invalid Playfair character encountered.");
        }

        let first;
        let second;
        let rule;

        if (a.row === b.row) {
            const direction = decrypt ? -1 : 1;

            first = grid[a.row][mod(a.col + direction, 5)];
            second = grid[b.row][mod(b.col + direction, 5)];

            rule = decrypt
                ? "same row → shift left"
                : "same row → shift right";
        } else if (a.col === b.col) {
            const direction = decrypt ? -1 : 1;

            first = grid[mod(a.row + direction, 5)][a.col];
            second = grid[mod(b.row + direction, 5)][b.col];

            rule = decrypt
                ? "same column → shift up"
                : "same column → shift down";
        } else {
            first = grid[a.row][b.col];
            second = grid[b.row][a.col];

            rule = "rectangle → swap columns";
        }

        const result = first + second;
        output += result;

        if (steps.length < 12) {
            steps.push(
                `${pair} → ${result} (${rule})`
            );
        }
    }

    return {
        output,
        formula: decrypt
            ? "Same row: left • Same column: up • Rectangle: swap columns"
            : "Same row: right • Same column: down • Rectangle: swap columns",
        steps,
        grid
    };
}

/* =========================================================
   HILL CIPHER HELPERS
========================================================= */

function parseHillMatrix(key) {
    const parts = key
        .split(",")
        .map(value => value.trim())
        .filter(value => value !== "");

    if (!parts.length) {
        throw new Error("Hill key cannot be empty.");
    }

    if (!parts.every(value => /^[-+]?\d+$/.test(value))) {
        throw new Error("Hill key must contain comma-separated integers.");
    }

    const values = parts.map(Number);
    const dimension = Math.sqrt(values.length);

    if (![2, 3, 4].includes(dimension) || !Number.isInteger(dimension)) {
        throw new Error(
            "Hill cipher supports only 2×2, 3×3 and 4×4 matrices."
        );
    }

    const matrix = [];

    for (let row = 0; row < dimension; row++) {
        matrix.push(
            values.slice(row * dimension, (row + 1) * dimension)
                .map(value => mod(value, 26))
        );
    }

    return matrix;
}

function matrixMinor(matrix, row, col) {
    return matrix
        .filter((_, r) => r !== row)
        .map(r => r.filter((_, c) => c !== col));
}

function determinant(matrix) {
    const n = matrix.length;

    if (n === 1) {
        return matrix[0][0];
    }

    if (n === 2) {
        return matrix[0][0] * matrix[1][1]
            - matrix[0][1] * matrix[1][0];
    }

    let det = 0;

    for (let col = 0; col < n; col++) {
        const sign = col % 2 === 0 ? 1 : -1;
        det += sign * matrix[0][col] * determinant(
            matrixMinor(matrix, 0, col)
        );
    }

    return det;
}

function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);

    while (b !== 0) {
        const temp = a % b;
        a = b;
        b = temp;
    }

    return a;
}

function modularInverse(value, modulus) {
    value = mod(value, modulus);

    for (let x = 1; x < modulus; x++) {
        if (mod(value * x, modulus) === 1) {
            return x;
        }
    }

    return null;
}

function matrixCofactor(matrix, row, col) {
    const sign = (row + col) % 2 === 0 ? 1 : -1;
    return sign * determinant(matrixMinor(matrix, row, col));
}

function transpose(matrix) {
    return matrix[0].map((_, col) =>
        matrix.map(row => row[col])
    );
}

function inverseMatrixMod26(matrix) {
    const det = determinant(matrix);
    const detMod = mod(det, 26);

    if (gcd(detMod, 26) !== 1) {
        throw new Error(
            "Invalid Hill Cipher key. The key matrix is not invertible modulo 26."
        );
    }

    const detInverse = modularInverse(detMod, 26);

    if (detInverse === null) {
        throw new Error(
            "Could not calculate the modular inverse of the determinant."
        );
    }

    const cofactorMatrix = matrix.map((row, r) =>
        row.map((_, c) => matrixCofactor(matrix, r, c))
    );

    const adjugate = transpose(cofactorMatrix);

    const inverse = adjugate.map(row =>
        row.map(value => mod(value * detInverse, 26))
    );

    return {
        determinant: det,
        determinantMod: detMod,
        determinantInverse: detInverse,
        inverse
    };
}

function multiplyMatrixVector(matrix, vector) {
    return matrix.map(row =>
        mod(
            row.reduce(
                (sum, value, index) => sum + value * vector[index],
                0
            ),
            26
        )
    );
}

function matrixToString(matrix) {
    return matrix
        .map(row => `[ ${row.join("  ")} ]`)
        .join("\n");
}

/* =========================================================
   HILL CIPHER
========================================================= */

function hillCipher(text, key, decrypt) {
    const matrix = parseHillMatrix(key);
    const dimension = matrix.length;

    let inverseData = null;

    if (decrypt) {
        inverseData = inverseMatrixMod26(matrix);
    }

    const clean = text
        .toUpperCase()
        .replace(/[^A-Z]/g, "");

    if (!clean) {
        throw new Error("Hill cipher requires at least one alphabetic character.");
    }

    let prepared = clean;

    while (prepared.length % dimension !== 0) {
        prepared += "X";
    }

    const workingMatrix = decrypt
        ? inverseData.inverse
        : matrix;

    const steps = [];
    let output = "";

    for (let i = 0; i < prepared.length; i += dimension) {
        const block = prepared.slice(i, i + dimension);
        const vector = block.split("").map(charToNumber);
        const resultVector = multiplyMatrixVector(workingMatrix, vector);
        const resultBlock = resultVector.map(numberToChar).join("");

        output += resultBlock;

        if (steps.length < 10) {
            steps.push(
                `${block} → [${vector.join(", ")}] → ` +
                `[${resultVector.join(", ")}] → ${resultBlock}`
            );
        }
    }

    const result = {
        output,
        formula: decrypt
            ? "P = K⁻¹ × C mod 26"
            : "C = K × P mod 26",
        steps,
        matrix
    };

    if (decrypt) {
        result.inverse = inverseData.inverse;
        result.inverseDetails = inverseData;
    }

    return result;
}

/* =========================================================
   ONE-TIME PAD
========================================================= */

function generateRandomOTPKey(length) {
    if (length <= 0) {
        return "";
    }

    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);

    let key = "";

    for (let i = 0; i < length; i++) {
        key += String.fromCharCode(65 + (randomValues[i] % 26));
    }

    return key;
}

function otpCipher(text, key, decrypt) {
    const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "");
    const letterCount = getLetters(text).length;

    if (!cleanKey) {
        throw new Error("OTP key must contain alphabetic characters.");
    }

    if (cleanKey.length !== letterCount) {
        throw new Error(
            `OTP key must contain exactly ${letterCount} letters.`
        );
    }

    let keyIndex = 0;
    let output = "";
    const steps = [];

    for (const char of text) {
        if (!isLetter(char)) {
            output += char;
            continue;
        }

        const p = charToNumber(char);
        const kChar = cleanKey[keyIndex];
        const k = charToNumber(kChar);

        const result = decrypt
            ? mod(p - k, 26)
            : mod(p + k, 26);

        const resultChar = numberToChar(result);

        output += preserveCase(char, resultChar);

        if (steps.length < 12) {
            steps.push(
                `${char} (${p}) ${decrypt ? "-" : "+"} ${kChar} (${k}) mod 26 = ${result} → ${resultChar}`
            );
        }

        keyIndex++;
    }

    return {
        output,
        formula: decrypt
            ? "Pᵢ = (Cᵢ − Kᵢ) mod 26"
            : "Cᵢ = (Pᵢ + Kᵢ) mod 26",
        steps
    };
}

/* =========================================================
   RAIL FENCE CIPHER
========================================================= */

function railFencePattern(length, rails) {
    const pattern = [];

    let rail = 0;
    let direction = 1;

    for (let i = 0; i < length; i++) {
        pattern.push(rail);

        if (rail === 0) {
            direction = 1;
        } else if (rail === rails - 1) {
            direction = -1;
        }

        rail += direction;
    }

    return pattern;
}

function validateRails(key, textLength) {
    const rails = Number(key);

    if (!Number.isInteger(rails)) {
        throw new Error("Rail Fence key must be an integer.");
    }

    if (rails < 2) {
        throw new Error("Rail Fence requires at least 2 rails.");
    }

    if (textLength > 0 && rails > textLength) {
        throw new Error("Number of rails cannot exceed message length.");
    }

    return rails;
}

function railFenceEncrypt(text, rails) {
    const pattern = railFencePattern(text.length, rails);
    const rows = Array.from({ length: rails }, () => []);

    for (let i = 0; i < text.length; i++) {
        rows[pattern[i]].push(text[i]);
    }

    return {
        output: rows.flat().join(""),
        pattern,
        rows
    };
}

function railFenceDecrypt(text, rails) {
    const pattern = railFencePattern(text.length, rails);
    const counts = Array(rails).fill(0);

    pattern.forEach(rail => counts[rail]++);

    const rows = Array.from({ length: rails }, () => []);

    let position = 0;

    for (let rail = 0; rail < rails; rail++) {
        rows[rail] = text.slice(position, position + counts[rail]).split("");
        position += counts[rail];
    }

    const indexes = Array(rails).fill(0);
    let output = "";

    for (const rail of pattern) {
        output += rows[rail][indexes[rail]];
        indexes[rail]++;
    }

    return {
        output,
        pattern,
        rows
    };
}

/* =========================================================
   RAIL FENCE CIPHER
========================================================= */

function railFenceCipher(text, key, decrypt) {
    const rails = validateRails(key, text.length);

    const result = decrypt
        ? railFenceDecrypt(text, rails)
        : railFenceEncrypt(text, rails);

    const steps = [];

    const pattern = result.pattern;

    for (let i = 0; i < Math.min(text.length, 20); i++) {
        steps.push(
            `Character ${i + 1}: "${text[i]}" → Rail ${pattern[i] + 1}`
        );
    }

    return {
        output: result.output,
        formula: decrypt
            ? "Reconstruct the zig-zag path, distribute ciphertext by rail, then read diagonally."
            : "Write characters in a zig-zag across the rails, then read each rail row-by-row.",
        steps,
        rails,
        pattern
    };
}

/* =========================================================
   VISUALIZATION HELPERS
========================================================= */

function createMatrixVisualization(title, matrix) {
    const wrapper = document.createElement("div");

    const heading = document.createElement("div");
    heading.className = "visual-title";
    heading.textContent = title;

    const table = document.createElement("table");
    table.className = "matrix";

    matrix.forEach(row => {
        const tr = document.createElement("tr");

        row.forEach(value => {
            const td = document.createElement("td");
            td.textContent = String(value);
            tr.appendChild(td);
        });

        table.appendChild(tr);
    });

    wrapper.appendChild(heading);
    wrapper.appendChild(table);

    return wrapper;
}

function createPlayfairVisualization(grid) {
    const wrapper = document.createElement("div");

    const heading = document.createElement("div");
    heading.className = "visual-title";
    heading.textContent = "Playfair 5×5 Key Square";

    const gridElement = document.createElement("div");
    gridElement.className = "playfair-grid";

    grid.flat().forEach(char => {
        const cell = document.createElement("div");
        cell.className = "playfair-cell";
        cell.textContent = char;
        gridElement.appendChild(cell);
    });

    wrapper.appendChild(heading);
    wrapper.appendChild(gridElement);

    return wrapper;
}

function createRailFenceVisualization(text, rails, pattern) {
    const wrapper = document.createElement("div");

    const heading = document.createElement("div");
    heading.className = "visual-title";
    heading.textContent = `Rail Fence Zig-Zag (${rails} rails)`;

    const diagram = document.createElement("div");
    diagram.className = "rail-fence";

    for (let rail = 0; rail < rails; rail++) {
        const row = document.createElement("div");
        row.className = "rail-row";

        for (let i = 0; i < text.length; i++) {
            const cell = document.createElement("div");
            cell.className = "rail-cell";

            if (pattern[i] === rail) {
                cell.textContent = text[i] === " " ? "␠" : text[i];
            } else {
                cell.classList.add("rail-empty");
                cell.textContent = "·";
            }

            row.appendChild(cell);
        }

        diagram.appendChild(row);
    }

    wrapper.appendChild(heading);
    wrapper.appendChild(diagram);

    return wrapper;
}

function renderVisualizations(result) {
    visualization.replaceChildren();

    if (state.algorithm === "playfair" && result.grid) {
        visualization.appendChild(
            createPlayfairVisualization(result.grid)
        );
    }

    if (state.algorithm === "hill" && result.matrix) {
        visualization.appendChild(
            createMatrixVisualization(
                "Hill Key Matrix",
                result.matrix
            )
        );

        if (result.inverse) {
            visualization.appendChild(
                createMatrixVisualization(
                    "Inverse Matrix Modulo 26",
                    result.inverse
                )
            );
        }
    }

    if (state.algorithm === "railfence" && result.pattern) {
        visualization.appendChild(
            createRailFenceVisualization(
                messageInput.value,
                result.rails,
                result.pattern
            )
        );
    }
}

/* =========================================================
   CONVERSION DISPATCHER
========================================================= */

function convert() {
    clearError();
    copyStatus.textContent = "";

    const text = messageInput.value;
    const key = keyInput.value.trim();

    if (!text) {
        setError("Please enter a message before converting.");
        messageInput.focus();
        return;
    }

    if (!key) {
        setError("Please enter a key.");
        keyInput.focus();
        return;
    }

    try {
        let result;

        switch (state.algorithm) {
            case "caesar":
                result = caesarCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            case "vigenere":
                result = vigenereCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            case "playfair":
                result = playfairCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            case "hill":
                result = hillCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            case "otp":
                result = otpCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            case "railfence":
                result = railFenceCipher(
                    text,
                    key,
                    state.operation === "decrypt"
                );
                break;

            default:
                throw new Error("Unknown cryptographic algorithm.");
        }

        displayResult(text, key, result);

    } catch (error) {
        setError(error.message);
        hideResults();
    }
}

/* =========================================================
   RESULT DISPLAY
========================================================= */

function displayResult(input, key, result) {
    resultAlgorithm.textContent = algorithmData[state.algorithm].name;
    resultOperation.textContent =
        state.operation === "encrypt" ? "Encryption" : "Decryption";

    resultKey.textContent = key;
    resultInput.textContent = input;
    resultOutput.textContent = result.output;

    formulaElement.textContent = result.formula;

    stepsList.replaceChildren();

    if (result.steps.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No letter-by-letter calculation was necessary.";
        stepsList.appendChild(li);
    } else {
        result.steps.forEach(step => {
            const li = document.createElement("li");
            li.textContent = step;
            stepsList.appendChild(li);
        });
    }

    renderVisualizations(result);

    resultSection.classList.remove("hidden");
    explanationSection.classList.remove("hidden");

    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

/* =========================================================
   EXAMPLES
========================================================= */

const examples = {
    caesar: {
        text: "HELLO",
        key: "3"
    },

    vigenere: {
        text: "ATTACKATDAWN",
        key: "LEMON"
    },

    playfair: {
        text: "INSTRUMENTS",
        key: "MONARCHY"
    },

    hill: {
        text: "HELP",
        key: "3,3,2,5"
    },

    otp: {
        text: "HELLO",
        key: "XMCKL"
    },

    railfence: {
        text: "WEAREDISCOVEREDFLEEATONCE",
        key: "3"
    }
};

function loadExample() {
    const example = examples[state.algorithm];

    messageInput.value = example.text;
    keyInput.value = example.key;

    state.operation = "encrypt";

    encryptBtn.classList.add("active");
    decryptBtn.classList.remove("active");

    clearError();
    hideResults();

    messageInput.focus();
}

/* =========================================================
   CLEAR
========================================================= */

function clearAll() {
    messageInput.value = "";
    keyInput.value = "";

    clearError();
    copyStatus.textContent = "";

    hideResults();

    visualization.replaceChildren();
    stepsList.replaceChildren();
    formulaElement.textContent = "";

    messageInput.focus();
}

/* =========================================================
   COPY
========================================================= */

async function copyResult() {
    const result = resultOutput.textContent;

    if (!result) {
        return;
    }

    try {
        await navigator.clipboard.writeText(result);
        copyStatus.textContent = "Copied successfully.";
    } catch {
        copyStatus.textContent =
            "Copy failed. Please select the output manually.";
    }

    setTimeout(() => {
        copyStatus.textContent = "";
    }, 2500);
}

/* =========================================================
   OTP RANDOM KEY
========================================================= */

function addOTPGenerator() {
    const existing = document.getElementById("otp-generate-btn");

    if (existing) {
        existing.remove();
    }

    if (state.algorithm !== "otp") {
        return;
    }

    const button = document.createElement("button");
    button.id = "otp-generate-btn";
    button.type = "button";
    button.className = "secondary-btn";
    button.textContent = "Generate Random Key";

    button.style.marginTop = "10px";

    button.addEventListener("click", () => {
        const letterCount = getLetters(messageInput.value);

        if (letterCount.length === 0) {
            setError(
                "Enter a message first so the random key can match its letter count."
            );
            return;
        }

        keyInput.value = generateRandomOTPKey(letterCount.length);
        clearError();
    });

    keyInput.parentElement.appendChild(button);
}

/* =========================================================
   EVENT LISTENERS
========================================================= */

algorithmCards.forEach(card => {
    card.addEventListener("click", () => {
        algorithmCards.forEach(item => {
            item.classList.remove("active");
        });

        card.classList.add("active");

        state.algorithm = card.dataset.algorithm;

        updateAlgorithmInfo();
        addOTPGenerator();

        clearError();
        hideResults();
    });
});

encryptBtn.addEventListener("click", () => {
    state.operation = "encrypt";

    encryptBtn.classList.add("active");
    decryptBtn.classList.remove("active");
});

decryptBtn.addEventListener("click", () => {
    state.operation = "decrypt";

    decryptBtn.classList.add("active");
    encryptBtn.classList.remove("active");
});

convertBtn.addEventListener("click", convert);

exampleBtn.addEventListener("click", loadExample);

clearBtn.addEventListener("click", clearAll);

copyBtn.addEventListener("click", copyResult);

messageInput.addEventListener("input", () => {
    if (state.algorithm === "otp") {
        addOTPGenerator();
    }

    clearError();
});

keyInput.addEventListener("input", clearError);

document.addEventListener("keydown", event => {
    if (
        (event.ctrlKey || event.metaKey) &&
        event.key === "Enter"
    ) {
        event.preventDefault();
        convert();
    }
});

/* =========================================================
   INITIALIZATION
========================================================= */

updateAlgorithmInfo();
addOTPGenerator();