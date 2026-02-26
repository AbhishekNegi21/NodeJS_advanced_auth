import QRcode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  throw new Error("Pass otpAuthUrl as arguments");
}

async function main() {
  await QRcode.toFile("totp.png", otpAuthUrl);
  console.log("Saved QR code");
}

main().catch((err) => {
  console.log(err);
  process.exit(1);
});
