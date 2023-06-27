# log

Package log provides a high level logger abstraction.

## Constants

```golang
const (
    // UnsetLevel should not be output by logger implementation.
    UnsetLevel = iota - 2
    // DebugLevel marks detailed output for design purposes.
    DebugLevel
    // InfoLevel is the default log output marker.
    InfoLevel
    // ErrorLevel marks an error output.
    ErrorLevel
)
```

## Functions

### func [SetFactory](static.go#L9)

`func SetFactory(f Factory)`

SetFactory sets the static logger factory.

## Types

### type [Factory](logger.go#L22)

`type Factory interface { ... }`

Factory defines a utility to create new loggers and set the log level threshold.

### type [Logger](logger.go#L28)

`type Logger interface { ... }`

Logger describes logger feature interface.

#### func [Error](static.go#L34)

`func Error(err error) Logger`

Error returns a new logger instance from the factory setting the error as supplied.

#### func [Field](static.go#L24)

`func Field(k string, v any) Logger`

Field returns a new logger instance from the factory setting a field value as supplied.

#### func [Fields](static.go#L29)

`func Fields(data map[string]any) Logger`

Fields returns a new logger instance from the factory setting field values as supplied.

#### func [Level](static.go#L19)

`func Level(lvl LoggerLevel) Logger`

Level returns a new logger instance from the factory setting its log level to the value supplied.

#### func [New](static.go#L14)

`func New() Logger`

New returns a new logger instance from the static factory.

### type [LoggerLevel](logger.go#L8)

`type LoggerLevel int`

LoggerLevel defines level markers for log entries.

