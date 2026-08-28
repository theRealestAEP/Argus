import {
	PutObjectCommand,
	S3Client,
	S3ServiceException,
} from "@aws-sdk/client-s3";

import type { ArchiveGateway } from "./s3-archive.js";

export function s3ArchiveGateway(client = new S3Client({})): ArchiveGateway {
	return {
		async put(upload) {
			try {
				const response = await client.send(new PutObjectCommand({
					Body: upload.body,
					Bucket: upload.bucket,
					BucketKeyEnabled: upload.kmsKeyId === undefined ? undefined : true,
					ChecksumSHA256: upload.checksumSha256,
					ContentEncoding: "gzip",
					ContentType: "application/json",
					IfNoneMatch: "*",
					Key: upload.key,
					Metadata: {
						"host-fingerprint": upload.hostFingerprint,
						"report-id": upload.reportId,
					},
					SSEKMSKeyId: upload.kmsKeyId,
					ServerSideEncryption: upload.kmsKeyId === undefined ? "AES256" : "aws:kms",
				}));
				return response.ETag ?? "uploaded";
			} catch (error) {
				if (error instanceof S3ServiceException && error.$metadata.httpStatusCode === 412) {
					return "already-exists";
				}
				throw error;
			}
		},
	};
}
