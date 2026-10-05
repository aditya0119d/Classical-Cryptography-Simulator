"use strict";

/*
    Classical Cryptography Simulator

    Algorithms:
    1. Caesar
    2. Vigenère
    3. Playfair
    4. Hill
    5. One-Time Pad
    6. Rail Fence

    Everything runs locally in the browser.
*/


/* =========================================================
   ALGORITHM INFORMATION
========================================================= */

const ALGOS = {

    caesar: {
        name: "Caesar Cipher",

        placeholder:
            "Enter shift value (e.g. 3)",

        help:
            "Key must be an integer. Negative shifts are supported.",

        desc:
            "Shifts every alphabetic character by a fixed amount.",

        key:
            "Integer shift",

        example:
            "HELLO + 3 → KHOOR",

        req:
            "Letters are shifted; spaces and punctuation stay unchanged.",

        formula:
            "Encrypt: C = (P + K) mod 26 | Decrypt: P = (C − K) mod 26"
    },


    vigenere: {
        name: "Vigenère Cipher",

        placeholder:
            "Enter keyword (e.g. SECRET)",

        help:
            "Key must contain at least one alphabetic character.",

        desc:
            "Applies a repeating keyword as a sequence of Caesar shifts.",

        key:
            "Alphabetic keyword",

        example:
            "ATTACKATDAWN + LEMON → LXFOPVEFRNHR",

        req:
            "The keyword advances only when a letter is processed.",

        formula:
            "Encrypt: Cᵢ = (Pᵢ + Kᵢ) mod 26 | Decrypt: Pᵢ = (Cᵢ − Kᵢ) mod 26"
    },


    playfair: {
        name: "Playfair Cipher",

        placeholder:
            "Enter keyword (e.g. MONARCHY)",

        help:
            "Keyword uses letters only; I and J share one cell.",

        desc:
            "Encrypts or decrypts digraphs using a 5×5 key square.",

        key:
            "Alphabetic keyword",

        example:
            "Keyword: MONARCHY",

        req:
            "J is merged with I. Encryption pads repeated pairs and odd final letters with X.",

        formula:
            "Same row: shift right/left. Same column: shift down/up. Rectangle: swap columns."
    },


    hill: {
        name: "Hill Cipher",

        placeholder:
            "Enter matrix key (e.g. 3,3,2,5)",

        help:
            "Enter n² integers for a 2×2, 3×3, or 4×4 matrix.",

        desc:
            "Multiplies letter vectors by a square matrix modulo 26.",

        key:
            "Comma-separated n² integers",

        example:
            "3,3,2,5 → [[3,3],[2,5]]",

        req:
            "For decryption, gcd(det(K), 26) must equal 1. X pads incomplete blocks.",

        formula:
            "Encrypt: C = K·P mod 26 | Decrypt: P = K⁻¹·C mod 26"
    },


    otp: {
        name: "One-Time Pad",

        placeholder:
            "Enter key with same length as text",

        help:
            "Key must have exactly the same number of letters as the message.",

        desc:
            "Adds a random key character to each message letter modulo 26.",

        key:
            "Alphabetic key of equal letter length",

        example:
            "HELLO + XMCKL → EQNVZ",

        req:
            "Use a truly random key once and keep it secret. Nonletters do not consume key characters.",

        formula:
            "Encrypt: Cᵢ = (Pᵢ + Kᵢ) mod 26 | Decrypt: Pᵢ = (Cᵢ − Kᵢ) mod 26"
    },


    railfence: {
        name: "Rail Fence Cipher",

        placeholder:
            "Enter number of rails (e.g. 3)",

        help:
            "Key must be an integer of at least 2.",

        desc:
            "Rearranges every character by writing it in a zig-zag across rails.",

        key:
            "Number of rails ≥ 2",

        example:
            "WEAREDISCOVEREDFLEEATONCE + 3 → WECRLTEERDSOEEFEAOCAIVDEN",

        req:
            "All characters, including spaces and punctuation, participate in the zig-zag.",

        formula:
            "Encryption: write zig-zag, then read rows. Decryption: reconstruct zig-zag positions, then read in order."
    }

};


/* =========================================================
   APPLICATION STATE
========================================================= */

const state = {
    algorithm: "caesar",
    operation: "encrypt",
    lastOutput: ""
};


/* =========================================================
   DOM HELPERS
========================================================= */

const $ = (id) => document.getElementById(id);


function setText(id, value) {
    $(id).textContent = value;
}


function showError(message) {

    const element = $("error-message");

    element.textContent = message || "";

    element.classList.toggle(
        "show",
        Boolean(message)
    );
}


/* =========================================================
   GENERAL HELPERS
========================================================= */

function mod(number, modulus) {
    return ((number % modulus) + modulus) % modulus;
}


function isLetter(character) {
    return /^[A-Za-z]$/.test(character);
}


function letterIndex(character) {
    return character.toUpperCase().charCodeAt(0) - 65;
}


function normalizeLetters(text) {

    return text
        .toUpperCase()
        .replace(/J/g, "I")
        .replace(/[^A-Z]/g, "");
}


/* =========================================================
   1. CAESAR CIPHER
========================================================= */

/*
    Formula:

    Encryption:
        C = (P + K) mod 26

    Decryption:
        P = (C - K) mod 26

    Non-alphabetic characters remain unchanged.
*/

function caesarCipher(text, key, operation) {

    const k = Number(key);

    const shift =
        operation === "encrypt"
            ? k
            : -k;

    const steps = [];

    let output = "";


    for (const character of text) {

        if (!isLetter(character)) {

            output += character;

            continue;
        }


        const plainIndex =
            letterIndex(character);

        const cipherIndex =
            mod(
                plainIndex + shift,
                26
            );


        const result =
            String.fromCharCode(
                65 + cipherIndex
            );


        output +=
            character === character.toUpperCase()
                ? result
                : result.toLowerCase();


        if (steps.length < 8) {

            steps.push(
                `${character} (${plainIndex}) ` +
                `${operation === "encrypt" ? "+" : "−"} ` +
                `${Math.abs(k)} → ` +
                `${result} (${cipherIndex})`
            );
        }
    }


    return {
        output,
        steps
    };
}


/* =========================================================
   2. VIGENÈRE CIPHER
========================================================= */

/*
    Formula:

    Encryption:
        Cᵢ = (Pᵢ + Kᵢ) mod 26

    Decryption:
        Pᵢ = (Cᵢ - Kᵢ) mod 26

    The key advances only when a letter is processed.
*/

function vigenereCipher(text, key, operation) {

    const cleanKey =
        key
            .toUpperCase()
            .replace(/[^A-Z]/g, "");


    if (!cleanKey) {

        throw new Error(
            "Vigenère key must contain at least one letter."
        );
    }


    let keyIndex = 0;

    let output = "";

    const steps = [];


    for (const character of text) {

        if (!isLetter(character)) {

            output += character;

            continue;
        }


        const plainIndex =
            letterIndex(character);

        const keyCharacter =
            cleanKey[
                keyIndex % cleanKey.length
            ];

        const keyValue =
            letterIndex(keyCharacter);


        const cipherIndex =
            mod(
                plainIndex +
                (
                    operation === "encrypt"
                        ? keyValue
                        : -keyValue
                ),
                26
            );


        const result =
            String.fromCharCode(
                65 + cipherIndex
            );


        output +=
            character === character.toUpperCase()
                ? result
                : result.toLowerCase();


        if (steps.length < 8) {

            steps.push(
                `${character} (${plainIndex}) ` +
                `${operation === "encrypt" ? "+" : "−"} ` +
                `${keyCharacter} (${keyValue}) → ` +
                `${result} (${cipherIndex})`
            );
        }


        keyIndex++;
    }


    return {
        output,
        steps
    };
}


/* =========================================================
   3. PLAYFAIR CIPHER
========================================================= */

function buildPlayfairSquare(key) {

    const letters =
        normalizeLetters(key);


    const seen =
        new Set();


    const sequence = [];


    const alphabet =
        "ABCDEFGHIKLMNOPQRSTUVWXYZ";


    for (const character of letters + alphabet) {

        if (!seen.has(character)) {

            seen.add(character);

            sequence.push(character);
        }
    }


    return Array.from(
        { length: 5 },
        (_, row) =>
            sequence.slice(
                row * 5,
                row * 5 + 5
            )
    );
}


function playfairPositions(square) {

    const positions = {};


    for (let row = 0; row < 5; row++) {

        for (let column = 0; column < 5; column++) {

            positions[
                square[row][column]
            ] = [row, column];
        }
    }


    return positions;
}


/*
    Prepare plaintext into digraphs.

    Example:

    BALLOON

    becomes:

    BA LX LO ON
*/

function preparePlayfairPlaintext(text) {

    const cleanText =
        normalizeLetters(text);


    const pairs = [];


    let index = 0;


    while (index < cleanText.length) {

        const first =
            cleanText[index];

        const second =
            cleanText[index + 1];


        if (!second) {

            pairs.push(
                first + "X"
            );

            index++;

        } else if (first === second) {

            pairs.push(
                first + "X"
            );

            index++;

        } else {

            pairs.push(
                first + second
            );

            index += 2;
        }
    }


    return pairs;
}


function preparePlayfairCiphertext(text) {

    const cleanText =
        normalizeLetters(text);


    if (cleanText.length % 2 !== 0) {

        throw new Error(
            "Playfair ciphertext must contain an even number of letters for decryption."
        );
    }


    return cleanText.match(/../g) || [];
}


function playfairPair(
    pair,
    square,
    operation
) {

    const positions =
        playfairPositions(square);


    const first =
        pair[0];

    const second =
        pair[1];


    const [row1, col1] =
        positions[first];

    const [row2, col2] =
        positions[second];


    /* Same row */

    if (row1 === row2) {

        const direction =
            operation === "encrypt"
                ? 1
                : -1;


        return (
            square[row1][
                mod(col1 + direction, 5)
            ] +

            square[row2][
                mod(col2 + direction, 5)
            ]
        );
    }


    /* Same column */

    if (col1 === col2) {

        const direction =
            operation === "encrypt"
                ? 1
                : -1;


        return (
            square[
                mod(row1 + direction, 5)
            ][col1] +

            square[
                mod(row2 + direction, 5)
            ][col2]
        );
    }


    /* Rectangle rule */

    return (
        square[row1][col2] +
        square[row2][col1]
    );
}


function playfairCipher(
    text,
    key,
    operation
) {

    const square =
        buildPlayfairSquare(key);


    const pairs =
        operation === "encrypt"
            ? preparePlayfairPlaintext(text)
            : preparePlayfairCiphertext(text);


    const steps = [];


    const output =
        pairs
            .map((pair) => {

                const result =
                    playfairPair(
                        pair,
                        square,
                        operation
                    );


                if (steps.length < 8) {

                    steps.push(
                        `${pair} → ${result}`
                    );
                }


                return result;
            })
            .join("");


    return {
        output,
        steps,

        visual: {
            type: "playfair",
            square
        }
    };
}


/* =========================================================
   4. HILL CIPHER
========================================================= */

function parseHillKey(key) {

    const numbers =
        key
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean)
            .map(Number);


    if (
        !numbers.length ||
        numbers.some(
            (value) =>
                !Number.isInteger(value) ||
                !Number.isFinite(value)
        )
    ) {

        throw new Error(
            "Hill key must contain only comma-separated integers."
        );
    }


    const size =
        Math.sqrt(numbers.length);


    if (
        ![2, 3, 4].includes(size) ||
        !Number.isInteger(size)
    ) {

        throw new Error(
            "Hill key must contain 4, 9, or 16 integers for a 2×2, 3×3, or 4×4 matrix."
        );
    }


    return Array.from(
        { length: size },
        (_, row) =>
            numbers
                .slice(
                    row * size,
                    row * size + size
                )
                .map((value) =>
                    mod(value, 26)
                )
    );
}


/* Recursive determinant calculation */

function determinant(matrix) {

    const size =
        matrix.length;


    if (size === 1) {

        return matrix[0][0];
    }


    if (size === 2) {

        return (
            matrix[0][0] * matrix[1][1] -
            matrix[0][1] * matrix[1][0]
        );
    }


    let result = 0;


    for (let column = 0; column < size; column++) {

        const minor =
            matrix
                .slice(1)
                .map((row) =>
                    row.filter(
                        (_, index) =>
                            index !== column
                    )
                );


        const sign =
            column % 2 === 0
                ? 1
                : -1;


        result +=
            sign *
            matrix[0][column] *
            determinant(minor);
    }


    return result;
}


function minorMatrix(
    matrix,
    rowToRemove,
    columnToRemove
) {

    return matrix
        .filter(
            (_, row) =>
                row !== rowToRemove
        )
        .map((row) =>
            row.filter(
                (_, column) =>
                    column !== columnToRemove
            )
        );
}


function adjugate(matrix) {

    const size =
        matrix.length;


    if (size === 1) {

        return [[1]];
    }


    const result =
        Array.from(
            { length: size },
            () =>
                Array(size).fill(0)
        );


    for (let row = 0; row < size; row++) {

        for (
            let column = 0;
            column < size;
            column++
        ) {

            const minor =
                minorMatrix(
                    matrix,
                    row,
                    column
                );


            const sign =
                (row + column) % 2 === 0
                    ? 1
                    : -1;


            /*
                Transpose while assigning,
                producing the adjugate matrix.
            */

            result[column][row] =
                sign *
                determinant(minor);
        }
    }


    return result;
}


/* Euclidean algorithm */

function gcd(a, b) {

    a = Math.abs(a);

    b = Math.abs(b);


    while (b !== 0) {

        const temporary =
            a % b;

        a = b;

        b = temporary;
    }


    return a;
}


/* Extended Euclidean algorithm */

function extendedGcd(a, b) {

    if (b === 0) {

        return [a, 1, 0];
    }


    const [
        gcdValue,
        x1,
        y1
    ] =
        extendedGcd(
            b,
            a % b
        );


    return [
        gcdValue,
        y1,
        x1 -
        Math.floor(a / b) * y1
    ];
}


/* Modular inverse */

function modInverse(number, modulus) {

    number =
        mod(number, modulus);


    const [
        gcdValue,
        x
    ] =
        extendedGcd(
            number,
            modulus
        );


    if (gcdValue !== 1) {

        throw new Error(
            `No modular inverse exists for ${number} modulo ${modulus}.`
        );
    }


    return mod(
        x,
        modulus
    );
}


/*
    Hill decryption:

    K⁻¹ =
    det(K)⁻¹ × adj(K) mod 26

    A matrix is invertible modulo 26
    only when gcd(det(K), 26) = 1.
*/

function matrixInverseMod26(matrix) {

    const determinantValue =
        determinant(matrix);


    const determinantMod =
        mod(
            determinantValue,
            26
        );


    if (
        gcd(
            determinantMod,
            26
        ) !== 1
    ) {

        throw new Error(
            `Hill matrix determinant is ${determinantValue}. gcd(det, 26) must be 1 for decryption.`
        );
    }


    const determinantInverse =
        modInverse(
            determinantMod,
            26
        );


    const adj =
        adjugate(matrix);


    return adj.map(
        (row) =>
            row.map(
                (value) =>
                    mod(
                        value *
                        determinantInverse,
                        26
                    )
            )
    );
}


function matrixVectorMultiply(
    matrix,
    vector
) {

    return matrix.map(
        (row) =>
            mod(
                row.reduce(
                    (sum, value, index) =>
                        sum +
                        value *
                        vector[index],
                    0
                ),
                26
            )
    );
}


function hillCipher(
    text,
    key,
    operation
) {

    const matrix =
        parseHillKey(key);


    const size =
        matrix.length;


    const inverse =
        operation === "decrypt"
            ? matrixInverseMod26(matrix)
            : null;


    const letters =
        text
            .toUpperCase()
            .replace(/[^A-Z]/g, "");


    if (!letters) {

        throw new Error(
            "Hill cipher needs at least one alphabetic character."
        );
    }


    let padded =
        letters;


    while (
        padded.length % size !== 0
    ) {

        padded += "X";
    }


    const selectedMatrix =
        operation === "encrypt"
            ? matrix
            : inverse;


    let output = "";

    const steps = [];


    for (
        let index = 0;
        index < padded.length;
        index += size
    ) {

        const block =
            padded.slice(
                index,
                index + size
            );


        const vector =
            [...block].map(
                letterIndex
            );


        const result =
            matrixVectorMultiply(
                selectedMatrix,
                vector
            );


        const resultText =
            result
                .map(
                    (value) =>
                        String.fromCharCode(
                            65 + value
                        )
                )
                .join("");


        output += resultText;


        if (steps.length < 6) {

            steps.push(
                `[${vector.join(", ")}] → ` +
                `[${result.join(", ")}] → ` +
                `${resultText}`
            );
        }
    }


    return {
        output,
        steps,

        visual: {
            type: "hill",
            matrix,
            inverse,
            padded
        }
    };
}


/* =========================================================
   5. ONE-TIME PAD
========================================================= */

/*
    OTP:

    Encryption:
        C = (P + K) mod 26

    Decryption:
        P = (C - K) mod 26

    Key must contain exactly as many
    letters as the message contains.
*/

function otpCipher(
    text,
    key,
    operation
) {

    const cleanKey =
        key
            .toUpperCase()
            .replace(/[^A-Z]/g, "");


    const letterCount =
        [...text]
            .filter(isLetter)
            .length;


    if (
        cleanKey.length !==
        letterCount
    ) {

        throw new Error(
            `OTP key must contain exactly ${letterCount} letters; received ${cleanKey.length}.`
        );
    }


    let keyIndex = 0;

    let output = "";

    const steps = [];


    for (const character of text) {

        if (!isLetter(character)) {

            output += character;

            continue;
        }


        const plainIndex =
            letterIndex(character);


        const keyCharacter =
            cleanKey[keyIndex];


        const keyValue =
            letterIndex(keyCharacter);


        const cipherIndex =
            mod(
                plainIndex +
                (
                    operation === "encrypt"
                        ? keyValue
                        : -keyValue
                ),
                26
            );


        const result =
            String.fromCharCode(
                65 + cipherIndex
            );


        output +=
            character === character.toUpperCase()
                ? result
                : result.toLowerCase();


        if (steps.length < 8) {

            steps.push(
                `${character} (${plainIndex}) ` +
                `${operation === "encrypt" ? "+" : "−"} ` +
                `${keyCharacter} (${keyValue}) → ` +
                `${result} (${cipherIndex})`
            );
        }


        keyIndex++;
    }


    return {
        output,
        steps
    };
}


/*
    Generate a random OTP key.

    crypto.getRandomValues() is used instead
    of Math.random().
*/

function generateOTPKey() {

    const letterCount =
        [...$("message").value]
            .filter(isLetter)
            .length;


    if (!letterCount) {

        showError(
            "Enter a message first so the simulator knows the required OTP key length."
        );

        return;
    }


    const randomBytes =
        new Uint8Array(
            letterCount
        );


    crypto.getRandomValues(
        randomBytes
    );


    const key =
        [...randomBytes]
            .map(
                (byte) =>
                    String.fromCharCode(
                        65 +
                        (byte % 26)
                    )
            )
            .join("");


    $("key").value = key;

    showError("");
}


/* =========================================================
   6. RAIL FENCE CIPHER
========================================================= */


/*
    Creates the rail number for every
    character position.

    Example for 3 rails:

    0 1 2 1 0 1 2 1 ...
*/

function railPattern(
    length,
    rails
) {

    const pattern = [];

    let rail = 0;

    let direction = 1;


    for (
        let index = 0;
        index < length;
        index++
    ) {

        pattern.push(rail);


        if (rails > 1) {

            if (rail === 0) {

                direction = 1;

            } else if (
                rail === rails - 1
            ) {

                direction = -1;
            }


            rail += direction;
        }
    }


    return pattern;
}


/*
    Rail Fence encryption:

        Write characters
        in zig-zag rails.

        Then read each rail
        from top to bottom.

    Rail Fence decryption:

        Recreate the zig-zag pattern.

        Count how many characters
        belong to each rail.

        Put ciphertext characters into
        those rails.

        Read them following the zig-zag.
*/

function railFenceCipher(
    text,
    key,
    operation
) {

    const rails =
        Number(key);


    if (
        !Number.isInteger(rails) ||
        rails < 2
    ) {

        throw new Error(
            "Rail Fence key must be an integer of at least 2."
        );
    }


    if (
        rails >= text.length &&
        text.length > 0
    ) {

        return {
            output: text,

            steps: [
                "The number of rails is at least the message length, so the text remains unchanged."
            ],

            visual: {
                type: "rail",
                text,
                rails
            }
        };
    }


    const pattern =
        railPattern(
            text.length,
            rails
        );


    let output = "";

    const steps = [];


    /* ================= ENCRYPT ================= */

    if (operation === "encrypt") {

        const rows =
            Array.from(
                { length: rails },
                () => []
            );


        [...text].forEach(
            (character, index) => {

                rows[
                    pattern[index]
                ].push(character);
            }
        );


        output =
            rows
                .map(
                    (row) =>
                        row.join("")
                )
                .join("");


        steps.push(
            "Zig-zag rail rows: " +
            rows
                .map(
                    (row, index) =>
                        `Rail ${index + 1}: ${row.join("")}`
                )
                .join(" | ")
        );
    }


    /* ================= DECRYPT ================= */

    else {

        const railCounts =
            Array(rails).fill(0);


        pattern.forEach(
            (rail) => {

                railCounts[rail]++;
            }
        );


        const rows = [];

        let position = 0;


        for (
            let rail = 0;
            rail < rails;
            rail++
        ) {

            rows[rail] =
                [
                    ...text.slice(
                        position,
                        position +
                        railCounts[rail]
                    )
                ];


            position +=
                railCounts[rail];
        }


        const indexes =
            Array(rails).fill(0);


        for (const rail of pattern) {

            output +=
                rows[rail][
                    indexes[rail]
                ];


            indexes[rail]++;
        }


        steps.push(
            "Rail character counts: " +
            railCounts.join(", ")
        );


        steps.push(
            "Characters are read back following the original zig-zag pattern."
        );
    }


    return {
        output,
        steps,

        visual: {
            type: "rail",
            text:
                operation === "encrypt"
                    ? text
                    : output,
            rails
        }
    };
}


/* =========================================================
   VISUALIZATION
========================================================= */

function createVisual(visual) {

    if (!visual) {
        return null;
    }


    const wrapper =
        document.createElement("div");


    /* ================= PLAYFAIR ================= */

    if (
        visual.type === "playfair"
    ) {

        const title =
            document.createElement("div");


        title.className =
            "viz-title";


        title.textContent =
            "Playfair 5×5 Key Square";


        wrapper.append(title);


        const grid =
            document.createElement("div");


        grid.className =
            "playfair-grid";


        visual.square
            .flat()
            .forEach((character) => {

                const cell =
                    document.createElement("div");


                cell.className =
                    "playfair-cell";


                cell.textContent =
                    character;


                grid.append(cell);
            });


        wrapper.append(grid);
    }


    /* ================= HILL ================= */

    else if (
        visual.type === "hill"
    ) {

        const title =
            document.createElement("div");


        title.className =
            "viz-title";


        title.textContent =
            "Hill Matrix";


        wrapper.append(title);


        wrapper.append(
            matrixTable(
                visual.matrix
            )
        );


        if (visual.inverse) {

            const inverseTitle =
                document.createElement("div");


            inverseTitle.className =
                "viz-title";


            inverseTitle.textContent =
                "Modular Inverse Matrix K⁻¹ (mod 26)";


            inverseTitle.style.marginTop =
                "15px";


            wrapper.append(
                inverseTitle
            );


            wrapper.append(
                matrixTable(
                    visual.inverse
                )
            );
        }


        const note =
            document.createElement("div");


        note.className =
            "field-help";


        note.textContent =
            `Working letters: ${visual.padded}`;


        wrapper.append(note);
    }


    /* ================= RAIL FENCE ================= */

    else if (
        visual.type === "rail"
    ) {

        const title =
            document.createElement("div");


        title.className =
            "viz-title";


        title.textContent =
            `Rail Fence Zig-Zag (${visual.rails} rails)`;


        wrapper.append(title);


        wrapper.append(
            railDiagram(
                visual.text,
                visual.rails
            )
        );
    }


    return wrapper;
}


/* =========================================================
   HILL MATRIX VISUALIZATION
========================================================= */

function matrixTable(matrix) {

    const table =
        document.createElement("table");


    table.className =
        "matrix";


    const tbody =
        document.createElement("tbody");


    matrix.forEach((row) => {

        const tableRow =
            document.createElement("tr");


        row.forEach((value) => {

            const cell =
                document.createElement("td");


            cell.textContent =
                String(value);


            tableRow.append(cell);
        });


        tbody.append(tableRow);
    });


    table.append(tbody);


    const wrapper =
        document.createElement("div");


    wrapper.className =
        "matrix-wrap";


    wrapper.append(table);


    return wrapper;
}


/* =========================================================
   RAIL FENCE VISUALIZATION
========================================================= */

function railDiagram(
    text,
    rails
) {

    const rows =
        Array.from(
            { length: rails },
            () =>
                Array(
                    text.length
                ).fill(" ")
        );


    const pattern =
        railPattern(
            text.length,
            rails
        );


    [...text].forEach(
        (character, index) => {

            rows[
                pattern[index]
            ][index] =
                character === " "
                    ? "·"
                    : character;
        }
    );


    const pre =
        document.createElement("pre");


    pre.className =
        "rail-diagram";


    pre.textContent =
        rows
            .map(
                (row, index) =>
                    `R${index + 1}  ${row.join("")}`
            )
            .join("\n");


    return pre;
}


/* =========================================================
   VALIDATION + CONVERSION
========================================================= */

function validateAndConvert() {

    showError("");


    const text =
        $("message").value;


    const key =
        $("key").value.trim();


    if (!text) {

        throw new Error(
            "Please enter a message first."
        );
    }


    let result;


    /* Caesar */

    if (
        state.algorithm === "caesar"
    ) {

        if (
            !/^[+-]?\d+$/.test(key)
        ) {

            throw new Error(
                "Caesar key must be an integer."
            );
        }


        result =
            caesarCipher(
                text,
                Number(key),
                state.operation
            );
    }


    /* Vigenère */

    else if (
        state.algorithm === "vigenere"
    ) {

        result =
            vigenereCipher(
                text,
                key,
                state.operation
            );
    }


    /* Playfair */

    else if (
        state.algorithm === "playfair"
    ) {

        if (
            !/[A-Za-z]/.test(key)
        ) {

            throw new Error(
                "Playfair key must contain at least one letter."
            );
        }


        result =
            playfairCipher(
                text,
                key,
                state.operation
            );
    }


    /* Hill */

    else if (
        state.algorithm === "hill"
    ) {

        result =
            hillCipher(
                text,
                key,
                state.operation
            );
    }


    /* OTP */

    else if (
        state.algorithm === "otp"
    ) {

        result =
            otpCipher(
                text,
                key,
                state.operation
            );
    }


    /* Rail Fence */

    else {

        result =
            railFenceCipher(
                text,
                key,
                state.operation
            );
    }


    state.lastOutput =
        result.output;


    showResult(
        text,
        key,
        result
    );


    return result;
}


/* =========================================================
   SHOW RESULT
========================================================= */

function showResult(
    input,
    key,
    result
) {

    $("result-section")
        .classList
        .remove("hidden");


    $("explanation-section")
        .classList
        .remove("hidden");


    setText(
        "result-algorithm",
        ALGOS[state.algorithm].name
    );


    setText(
        "result-operation",
        state.operation.toUpperCase()
    );


    setText(
        "result-key",
        key
    );


    setText(
        "result-input",
        input
    );


    setText(
        "result-output",
        result.output
    );


    setText(
        "formula",
        ALGOS[state.algorithm].formula
    );


    const stepsList =
        $("steps-list");


    stepsList.replaceChildren();


    result.steps.forEach(
        (step) => {

            const listItem =
                document.createElement("li");


            listItem.textContent =
                step;


            stepsList.append(listItem);
        }
    );


    const visualization =
        $("visualization");


    visualization.replaceChildren();


    const visual =
        createVisual(
            result.visual
        );


    if (visual) {

        visualization.append(
            visual
        );
    }


    $("result-section")
        .scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
}


/* =========================================================
   UPDATE ALGORITHM UI
========================================================= */

function updateAlgorithmUI() {

    const algorithm =
        ALGOS[state.algorithm];


    setText(
        "info-text",
        algorithm.desc
    );


    setText(
        "info-key",
        algorithm.key
    );


    setText(
        "info-example",
        algorithm.example
    );


    setText(
        "info-requirements",
        algorithm.req
    );


    $("key").placeholder =
        algorithm.placeholder;


    setText(
        "key-help",
        algorithm.help
    );


    $("generate-key-btn")
        .classList
        .toggle(
            "hidden",
            state.algorithm !== "otp"
        );


    showError("");


    document
        .querySelectorAll(".algorithm-card")
        .forEach((button) => {

            button.classList.toggle(
                "active",
                button.dataset.algorithm ===
                state.algorithm
            );
        });
}


/* =========================================================
   LOAD EXAMPLE
========================================================= */

function loadExample() {

    const samples = {

        caesar: {
            text: "HELLO",
            key: "3",
            operation: "encrypt"
        },

        vigenere: {
            text: "ATTACKATDAWN",
            key: "LEMON",
            operation: "encrypt"
        },

        playfair: {
            text: "INSTRUMENTS",
            key: "MONARCHY",
            operation: "encrypt"
        },

        hill: {
            text: "HELP",
            key: "3,3,2,5",
            operation: "encrypt"
        },

        otp: {
            text: "HELLO",
            key: "XMCKL",
            operation: "encrypt"
        },

        railfence: {
            text: "WEAREDISCOVEREDFLEEATONCE",
            key: "3",
            operation: "encrypt"
        }

    };


    const sample =
        samples[state.algorithm];


    $("message").value =
        sample.text;


    $("key").value =
        sample.key;


    setOperation(
        sample.operation
    );


    showError("");
}


/* =========================================================
   SET ENCRYPT / DECRYPT
========================================================= */

function setOperation(operation) {

    state.operation =
        operation;


    $("encrypt-btn")
        .classList
        .toggle(
            "active",
            operation === "encrypt"
        );


    $("decrypt-btn")
        .classList
        .toggle(
            "active",
            operation === "decrypt"
        );
}


/* =========================================================
   CLEAR
========================================================= */

function clearAll() {

    $("message").value = "";

    $("key").value = "";


    $("result-section")
        .classList
        .add("hidden");


    $("explanation-section")
        .classList
        .add("hidden");


    $("steps-list")
        .replaceChildren();


    $("visualization")
        .replaceChildren();


    setText(
        "copy-status",
        ""
    );


    state.lastOutput = "";


    showError("");
}


/* =========================================================
   COPY RESULT
========================================================= */

async function copyResult() {

    if (!state.lastOutput) {

        return;
    }


    try {

        await navigator.clipboard.writeText(
            state.lastOutput
        );


        setText(
            "copy-status",
            "Copied!"
        );


        setTimeout(() => {

            setText(
                "copy-status",
                ""
            );

        }, 1800);

    } catch (error) {

        showError(
            "Clipboard access was unavailable. Select and copy the output manually."
        );
    }
}


/* =========================================================
   INITIALIZE APPLICATION
========================================================= */

window.addEventListener(
    "DOMContentLoaded",
    () => {

        updateAlgorithmUI();


        /*
            Algorithm selection
        */

        document
            .querySelectorAll(".algorithm-card")
            .forEach((button) => {

                button.addEventListener(
                    "click",
                    () => {

                        state.algorithm =
                            button.dataset.algorithm;


                        updateAlgorithmUI();
                    }
                );
            });


        /*
            Encryption / decryption
        */

        $("encrypt-btn")
            .addEventListener(
                "click",
                () => {

                    setOperation(
                        "encrypt"
                    );
                }
            );


        $("decrypt-btn")
            .addEventListener(
                "click",
                () => {

                    setOperation(
                        "decrypt"
                    );
                }
            );


        /*
            Load example
        */

        $("example-btn")
            .addEventListener(
                "click",
                loadExample
            );


        /*
            OTP random key
        */

        $("generate-key-btn")
            .addEventListener(
                "click",
                generateOTPKey
            );


        /*
            Clear
        */

        $("clear-btn")
            .addEventListener(
                "click",
                clearAll
            );


        /*
            Convert
        */

        $("convert-btn")
            .addEventListener(
                "click",
                () => {

                    try {

                        validateAndConvert();

                    } catch (error) {

                        showError(
                            error.message ||
                            "Unable to convert the message."
                        );
                    }
                }
            );


        /*
            Copy
        */

        $("copy-btn")
            .addEventListener(
                "click",
                copyResult
            );

    }
);