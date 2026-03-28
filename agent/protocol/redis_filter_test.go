package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedisFilter_Filter(t *testing.T) {
	type fields struct {
		TargetCommands   []string
		ExcludedCommands []string
		TargetKeys       []string
		KeyPrefix        string
	}
	type args struct {
		req ParsedMessage
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "filter_by_target_command",
			fields: fields{
				TargetCommands: []string{"GET"},
			},
			args: args{
				req: &RedisMessage{command: "GET", payload: "user:1"},
			},
			want: true,
		},
		{
			name: "exclude_command_blocks_match",
			fields: fields{
				ExcludedCommands: []string{"INFO", "CLUSTER"},
			},
			args: args{
				req: &RedisMessage{command: "INFO", payload: "stats"},
			},
			want: false,
		},
		{
			name: "exclude_command_is_case_insensitive",
			fields: fields{
				ExcludedCommands: []string{"info", "cluster"},
			},
			args: args{
				req: &RedisMessage{command: "INFO", payload: "stats"},
			},
			want: false,
		},
		{
			name: "exclude_command_does_not_block_other_commands",
			fields: fields{
				ExcludedCommands: []string{"INFO", "CLUSTER"},
			},
			args: args{
				req: &RedisMessage{command: "GET", payload: "user:1"},
			},
			want: true,
		},
		{
			name: "target_and_excluded_command_prefers_exclusion",
			fields: fields{
				TargetCommands:   []string{"INFO"},
				ExcludedCommands: []string{"INFO"},
			},
			args: args{
				req: &RedisMessage{command: "INFO", payload: "stats"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := RedisFilter{
				TargetCommands:   tt.fields.TargetCommands,
				ExcludedCommands: tt.fields.ExcludedCommands,
				TargetKeys:       tt.fields.TargetKeys,
				KeyPrefix:        tt.fields.KeyPrefix,
			}
			assert.Equal(t, tt.want, filter.Filter(tt.args.req, nil))
		})
	}
}

func TestRedisFilter_FilterByRequest(t *testing.T) {
	filter := RedisFilter{
		ExcludedCommands: []string{"INFO"},
	}

	assert.True(t, filter.FilterByRequest())
}
