// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function zodToJsonSchema(zodSchema: any): Record<string, unknown> {
  const shape = zodSchema._def.shape?.() || zodSchema.shape;

  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];

  for (const [key, value] of Object.entries(shape)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const field = value as any;
    const fieldDef = field._def;

    let type = 'string';
    let description = fieldDef.description || '';
    let items: Record<string, unknown> | undefined;
    let enumValues: string[] | undefined;
    let defaultValue: unknown;

    if (fieldDef.typeName === 'ZodString') {
      type = 'string';
    } else if (fieldDef.typeName === 'ZodNumber') {
      type = 'number';
    } else if (fieldDef.typeName === 'ZodBoolean') {
      type = 'boolean';
    } else if (fieldDef.typeName === 'ZodArray') {
      type = 'array';
      const innerType = fieldDef.type?._def?.typeName;
      if (innerType === 'ZodString') {
        items = { type: 'string' };
      } else if (innerType === 'ZodEnum') {
        items = { type: 'string', enum: fieldDef.type._def.values };
      } else {
        items = { type: 'string' };
      }
    } else if (fieldDef.typeName === 'ZodEnum') {
      type = 'string';
      enumValues = fieldDef.values;
    } else if (fieldDef.typeName === 'ZodDefault') {
      const inner = fieldDef.innerType._def;
      defaultValue = fieldDef.defaultValue();

      if (inner.typeName === 'ZodString') {
        type = 'string';
      } else if (inner.typeName === 'ZodNumber') {
        type = 'number';
      } else if (inner.typeName === 'ZodBoolean') {
        type = 'boolean';
      } else if (inner.typeName === 'ZodArray') {
        type = 'array';
        const arrayInner = inner.type?._def;
        if (arrayInner?.typeName === 'ZodEnum') {
          items = { type: 'string', enum: arrayInner.values };
        } else {
          items = { type: 'string' };
        }
      } else if (inner.typeName === 'ZodEnum') {
        type = 'string';
        enumValues = inner.values;
      }

      description = inner.description || description;
    } else if (fieldDef.typeName === 'ZodOptional') {
      const inner = fieldDef.innerType._def;
      if (inner.typeName === 'ZodString') {
        type = 'string';
      } else if (inner.typeName === 'ZodNumber') {
        type = 'number';
      } else if (inner.typeName === 'ZodRecord') {
        type = 'object';
      } else if (inner.typeName === 'ZodArray') {
        type = 'array';
        items = { type: 'string' };
      } else if (inner.typeName === 'ZodObject') {
        type = 'object';
      }
      description = inner.description || description;
    } else if (fieldDef.typeName === 'ZodRecord') {
      type = 'object';
    } else if (fieldDef.typeName === 'ZodObject') {
      type = 'object';
    }

    const prop: Record<string, unknown> = { type, description };
    if (items) prop.items = items;
    if (enumValues) prop.enum = enumValues;
    if (defaultValue !== undefined) prop.default = defaultValue;

    properties[key] = prop;

    if (!fieldDef.typeName?.includes('Optional') && !fieldDef.typeName?.includes('Default')) {
      required.push(key);
    }
  }

  const schema: Record<string, unknown> = {
    type: 'object',
    properties
  };

  if (required.length > 0) {
    schema.required = required;
  }

  return schema;
}
