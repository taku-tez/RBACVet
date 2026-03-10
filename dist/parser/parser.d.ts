import { ParseResult } from './types';
export declare function parseFile(content: string, filePath: string): ParseResult;
export declare function parseFiles(files: {
    path: string;
    content: string;
}[]): ParseResult;
