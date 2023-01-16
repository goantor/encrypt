package encrypt

import "reflect"

type Types struct {
	data interface{}
	kind reflect.Kind
}

func NewTypes(data interface{}) *Types {
	return &Types{data: data, kind: reflect.TypeOf(data).Kind()}
}

func (t Types) isString() bool {
	return t.kind == reflect.String
}

func (t Types) isBytes() bool {
	return t.kind == reflect.Slice
}

func (t Types) String() string {
	if t.isString() {
		return t.data.(string)
	}

	return string(t.data.([]byte))
}

func (t Types) Bytes() []byte {
	if t.isBytes() {
		return t.data.([]byte)
	}

	return []byte(t.data.(string))
}
