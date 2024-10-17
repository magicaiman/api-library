import jwt from "jsonwebtoken";
import { notFound } from "../error/NotFoundError";
import { User } from "../models/user.model";

const JWT_SECRET = "nklndfgkdfgklndgfnkldfgdfgkln";

export class AuthentificationService {
    public async auth(username: string, password: string): Promise<string> {
        const token = jwt.sign({ username: username }, JWT_SECRET, {
            expiresIn: "1h"
        });
        return token;
    }

    public async authenticate(username: string, password: string): Promise<string> {
        const user = await User.findOne({ where: { username: username } });

        if (!user) {
            throw notFound("User not found");
        }

        const decodedPaxxword = Buffer.from(user.password, 'base64').toString('utf-8');

        if (password === decodedPaxxword) {
            const token = jwt.sign({ username: username }, JWT_SECRET, {
                expiresIn: "1h"
            });
            return token;
        } else {
            let error = new Error("Invalid password");
            (error as any).status = 403;
            throw error;
        }
    }
}

export const authService = new AuthentificationService();