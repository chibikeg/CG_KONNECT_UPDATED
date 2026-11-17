const crypto = require('crypto');

const safeHexCompare = (expectedHex, actualHex) =>{
    if(!/^[0-9a-f]{128}$/.test(actualHex || "")) return false;

    const expected = Buffer.from(expectedHex, "hex");
    const actual = Buffer.from(actualHex, "hex");

    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
}

const verifyPaystackWebhook = (req) => {
    const rawBody = req.rawBody;
    if(!rawBody) return false;

    const modernHeader = req.headers["paystack-signature"];

    if(modernHeader && process.env.PAYSTACK_WEBHOOK_SECRET){
        const parts = modernHeader.split(",");
        const timeStamp = parts.find((part)=> part.startsWith("t=")) ?.slice(2);
        const signature = parts.filter((part) => part.startsWith("v1=")).map((part) => part.slice(3).split(":").pop());
        const timeStampNumber = Number(timeStamp);
        if(!Number.isFinite(timeStampNumber)) return false;

        const ageSeconds = Math.abs(Date.now() / 1000 - timeStampNumber);
        if(ageSeconds > 300) return false;

        const expected = crypto
            .createHmac("sha512", process.env.PAYSTACK_WEBHOOK_SECRET)
            .update(`${timeStamp}.`)
            .update(rawBody)
            .digest("hex")

        return signature.some((signatures) => safeHexCompare(expected, signatures))
    }


    const legacySignature = req.headers["x-paaystack-signature"];
    if(!legacySignature || !process.env.PAYSTACK_WEBHOOK_SECRET) return false;

    const expected = crypto
            .createHmac("sha512", process.env.PAYSTACK_WEBHOOK_SECRET)
            .update(rawBody)
            .digest("hex");
    
    return safeHexCompare(expected, legacySignature);
}

module.exports = verifyPaystackWebhook;