import jwt from "jsonwebtoken";
import { notFound } from "../error/NotFoundError";
import { User } from "../models/user.model";

const JWT_SECRET = "nklndfgkdfgklndgfnkldfgdfgkln";

export class AuthentificationService {
    public async authenticate(username: string, password: string): Promise<string> {
        const user = await User.findOne({ where: { username: username } });

        if (!user) {
            throw notFound("User not found");
        }

        // Décoder le mot de passe de l'utilisateur
        const decodedPassword = Buffer.from(user.password, 'base64').toString('utf-8');

        if (password === decodedPassword) {
            const scopes = this.getScopes(username);
            const token = jwt.sign({ username: user.username, scopes }, JWT_SECRET, {
                expiresIn: "1h",
            });
            return token;
        } else {
            let error = new Error("Invalid password");
            (error as any).status = 403;
            throw error;
        }
    }


    private getScopes(username: string): string[] {
        switch (username) {
            case 'admin':
                return [
                    'author:read',
                    'author:create',
                    'author:delete',
                    'book:read',
                    'book:create',
                    'book:delete',
                    'bookCollection:read',
                    'bookCollection:create',
                    'bookCollection:delete',
                ];
            case 'gerant':
                return [
                    'author:read',
                    'book:read',
                    'book:create',
                    'book:delete',
                    'bookCollection:read',
                    'bookCollection:create',
                    'bookCollection:delete',
                ];
            case 'utilisateur':
                return [
                    'book:read',
                    'book:create',
                ];
            default:
                return [];
        }
    }
}

export const authService = new AuthentificationService();
