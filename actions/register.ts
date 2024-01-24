"use server";

import { generateVerificationToken } from "@/data/tokens";
import { getUserByEmail } from "@/data/user";
import { db } from "@/lib/db";
import { sendVerificationEmail } from "@/lib/mail";
import { RegisterSchema } from "@/schemas";
import { hash } from "bcryptjs";
import { z } from "zod";

export const register = async (values: z.infer<typeof RegisterSchema>) => {
  const validateFields = RegisterSchema.safeParse(values);

  if (!validateFields.success) {
    return { error: "Invalid fields!" };
  }

  const { email, name, password } = validateFields.data;
  const hashedPassword = await hash(password, 10);

  const existingEmail = await getUserByEmail(email);

  if (existingEmail) {
    return { error: "Email already used" };
  }

  await db.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  const verificationToken = await generateVerificationToken(email);
  await sendVerificationEmail(verificationToken.email, verificationToken.token);

  return { success: "Confirmation email sent" };
};
