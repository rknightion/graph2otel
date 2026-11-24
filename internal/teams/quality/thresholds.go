// Package quality defines the Teams media classifier's operator-tunable limits.
package quality

import (
	"fmt"
	"math"
)

// Thresholds uses CQD's packet, millisecond, ratio, percent and fps units.
// Zero is a valid override, not a request to use the default.
type Thresholds struct {
	MinPackets       int64   `yaml:"min_packets"`
	AudioRTTMs       float64 `yaml:"audio_rtt_ms"`
	AudioPacketLoss  float64 `yaml:"audio_packet_loss_ratio"`
	AudioJitterMs    float64 `yaml:"audio_jitter_ms"`
	VideoFrameLoss   float64 `yaml:"video_frame_loss_percent"`
	VideoFrameRate   float64 `yaml:"video_frame_rate_fps"`
	VideoPostFECLoss float64 `yaml:"video_post_fec_loss_ratio"`
	VBSSFrameRate    float64 `yaml:"vbss_frame_rate_fps"`
}

// DefaultThresholds returns the documented limits from Microsoft CQD:
// https://learn.microsoft.com/en-us/microsoftteams/stream-classification-in-call-quality-dashboard
func DefaultThresholds() Thresholds {
	return Thresholds{
		// #audio-classifier and #video-classifier
		MinPackets: 500,
		// #audio-classifier
		AudioRTTMs: 500, AudioPacketLoss: 0.1, AudioJitterMs: 30,
		// #video-classifier
		VideoFrameLoss: 50, VideoFrameRate: 7, VideoPostFECLoss: 0.15,
		// #vbss-classifier (H264S, either direction)
		VBSSFrameRate: 1,
	}
}

// Validate rejects invalid limits after YAML and environment overrides merge.
func (q Thresholds) Validate() error {
	// Helm's JSON numbers and the evidence log's numeric values must retain
	// this threshold exactly.
	if q.MinPackets < 0 || q.MinPackets > 1<<53-1 {
		return fmt.Errorf("teams.quality_thresholds.min_packets: expected an integer between 0 and 9007199254740991")
	}
	for _, item := range [...]struct {
		key          string
		value, limit float64
	}{
		{"audio_rtt_ms", q.AudioRTTMs, math.Inf(1)},
		{"audio_jitter_ms", q.AudioJitterMs, math.Inf(1)},
		{"audio_packet_loss_ratio", q.AudioPacketLoss, 1},
		{"video_frame_loss_percent", q.VideoFrameLoss, 100},
		{"video_frame_rate_fps", q.VideoFrameRate, math.Inf(1)},
		{"video_post_fec_loss_ratio", q.VideoPostFECLoss, 1},
		{"vbss_frame_rate_fps", q.VBSSFrameRate, math.Inf(1)},
	} {
		const prefix = "teams.quality_thresholds."
		switch {
		case math.IsNaN(item.value) || math.IsInf(item.value, 0) || item.value < 0:
			return fmt.Errorf("%s%s: expected a finite non-negative number", prefix, item.key)
		case item.value > item.limit && item.limit == 1:
			return fmt.Errorf("%s%s: expected a ratio between 0 and 1", prefix, item.key)
		case item.value > item.limit:
			return fmt.Errorf("%s%s: expected a percentage between 0 and 100", prefix, item.key)
		}
	}
	return nil
}
