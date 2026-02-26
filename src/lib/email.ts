import nodemailer from "nodemailer";

export async function sendEmail(to: string, subject: string, html: string) {
  // check if smtp credentials are present
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
  ) {
    console.log("Email envs are not present");
    return;
  }

  // store the env data into variables
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || "2525");
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.EMAIL_FROM;

  // create a transporter
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: false,
    auth: {
      user,
      pass,
    },
  });

  // call the "sendMail" method from transporter to send mails
  await transporter.sendMail({
    from,
    to,
    subject,
    html,
  });
}
