import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';

// Fonction d'authentification
export const expressAuthentication = (
    request: Request,
    securityName: string,
    scopes?: string[]
): Promise<any> => {
    if (securityName === 'jwt') {
        const token = request.headers.authorization?.split(' ')[1];

        if (!token) {
            return Promise.reject({
                status: 401,
                message: 'Token non fourni'
            });
        }

        return new Promise((resolve, reject) => {
            jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded: any) => {
                if (err) {
                    return reject({
                        status: 401,
                        message: 'Token invalide'
                    });
                }

                // Si des scopes sont définis, vérifier les permissions
                if (scopes && !scopes.every(scope => decoded.scopes?.includes(scope))) {
                    return reject({
                        status: 403,
                        message: 'Permissions insuffisantes'
                    });
                }

                resolve(decoded);
            });
        });
    }

    return Promise.reject({
        status: 401,
        message: 'Authentification non supportée'
    });
};