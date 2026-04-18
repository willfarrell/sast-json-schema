import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import { Bench } from "tinybench";
import schema from "./2020-12.json" with { type: "json" };

test("perf: schema validation benchmarks", async () => {
	const ajv = new Ajv({ strictTypes: false });
	const validate = ajv.compile(schema);

	const suite = new Bench({ name: "sast-json-schema" });

	const secureSchema = {
		type: "object",
		properties: {
			name: { type: "string", format: "email", maxLength: 100 },
		},
		required: ["name"],
		unevaluatedProperties: false,
	};

	const insecureSchema = {
		type: "object",
		properties: {
			name: { type: "string" },
			items: { type: "array", items: { type: "string" } },
		},
	};

	const complexSchema = {
		type: "object",
		properties: {
			name: { type: "string", maxLength: 100, pattern: "^[a-z]+$" },
			age: { type: "integer", minimum: 0, maximum: 150 },
			tags: {
				type: "array",
				items: { type: "string", maxLength: 50 },
				maxItems: 10,
				uniqueItems: true,
				unevaluatedItems: false,
			},
		},
		required: ["name"],
		unevaluatedProperties: false,
	};

	const deeplyNestedSchema = {
		type: "object",
		properties: {
			user: {
				allOf: [
					{
						type: "object",
						properties: {
							name: { type: "string", maxLength: 100, pattern: "^[a-z]+$" },
						},
						required: ["name"],
						unevaluatedProperties: false,
					},
					{
						anyOf: [
							{
								type: "object",
								properties: {
									role: {
										allOf: [
											{
												type: "string",
												maxLength: 50,
												enum: ["admin", "user", "guest"],
											},
										],
									},
									level: {
										type: "integer",
										minimum: 0,
										maximum: 100,
									},
								},
								required: ["role", "level"],
								unevaluatedProperties: false,
							},
							{
								type: "object",
								properties: {
									group: {
										anyOf: [
											{
												type: "string",
												maxLength: 50,
												enum: ["engineering", "sales"],
											},
											{
												type: "string",
												maxLength: 50,
												enum: ["support", "marketing"],
											},
										],
									},
								},
								required: ["group"],
								unevaluatedProperties: false,
							},
						],
					},
				],
			},
		},
		required: ["user"],
		unevaluatedProperties: false,
	};

	const manyPatternsSchema = {
		type: "object",
		properties: {
			username: {
				type: "string",
				maxLength: 50,
				pattern: "^[a-zA-Z0-9_-]+$",
			},
			email: { type: "string", maxLength: 254, format: "email" },
			phone: {
				type: "string",
				maxLength: 20,
				pattern: "^[0-9+() -]+$",
			},
			zipCode: {
				type: "string",
				maxLength: 10,
				pattern: "^[0-9]{5}(-[0-9]{4})?$",
			},
			country: {
				type: "string",
				maxLength: 2,
				pattern: "^[A-Z]{2}$",
			},
			locale: {
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]{2}(-[A-Z]{2})?$",
			},
			slug: {
				type: "string",
				maxLength: 100,
				pattern: "^[a-z0-9]+(-[a-z0-9]+)*$",
			},
			hexColor: {
				type: "string",
				maxLength: 7,
				pattern: "^#[0-9a-fA-F]{6}$",
			},
		},
		required: [
			"username",
			"email",
			"phone",
			"zipCode",
			"country",
			"locale",
			"slug",
			"hexColor",
		],
		unevaluatedProperties: false,
	};

	const largeEnumSchema = {
		type: "string",
		maxLength: 100,
		enum: [
			"pending",
			"active",
			"inactive",
			"suspended",
			"deleted",
			"archived",
			"draft",
			"published",
			"review",
			"approved",
			"rejected",
			"cancelled",
			"expired",
			"processing",
			"completed",
			"failed",
			"queued",
			"running",
			"paused",
			"stopped",
			"error",
			"timeout",
			"retrying",
			"blocked",
			"waiting",
			"assigned",
			"unassigned",
			"escalated",
			"resolved",
			"closed",
			"reopened",
			"merged",
			"locked",
			"unlocked",
			"verified",
			"unverified",
			"enabled",
			"disabled",
			"deprecated",
			"migrated",
			"synced",
			"desynced",
			"connected",
			"disconnected",
			"online",
			"offline",
			"maintenance",
			"degraded",
			"healthy",
			"unhealthy",
		],
	};

	suite
		.add("validate secure schema", () => {
			validate(secureSchema);
		})
		.add("validate insecure schema", () => {
			validate(insecureSchema);
		})
		.add("validate complex schema", () => {
			validate(complexSchema);
		})
		.add("compile + validate", () => {
			const v = ajv.compile(schema);
			v(secureSchema);
			ajv.removeSchema();
		})
		.add("validate deeply nested schema", () => {
			validate(deeplyNestedSchema);
		})
		.add("validate many patterns schema", () => {
			validate(manyPatternsSchema);
		})
		.add("validate large enum schema", () => {
			validate(largeEnumSchema);
		});

	await suite.run();
	console.table(suite.table());
});
