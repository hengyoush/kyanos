package common

type BaseError struct {
	msg string
}

func (e *BaseError) Error() string {
	return e.msg
}

type InvalidArgument struct {
	BaseError
}

func NewInvalidArgument(msg string) *InvalidArgument {
	return &InvalidArgument{
		BaseError: BaseError{msg},
	}
}
