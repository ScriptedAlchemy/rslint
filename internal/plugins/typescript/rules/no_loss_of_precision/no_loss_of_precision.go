package no_loss_of_precision

import (
	"github.com/web-infra-dev/rslint/internal/rule"
	core_no_loss_of_precision "github.com/web-infra-dev/rslint/internal/rules/no_loss_of_precision"
)

var NoLossOfPrecisionRule = rule.CreateRule(rule.Rule{
	Name: "no-loss-of-precision",
	Run:  core_no_loss_of_precision.NoLossOfPrecisionRule.Run,
})
