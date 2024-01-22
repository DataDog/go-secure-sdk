// Package masking provides various data masking used to reduce data value relevance and linkability.
//
// ## Introduction
//
// (credits to https://www.techtarget.com/searchsecurity/tip/Data-masking-vs-data-encryption-How-do-they-differ)
//
// ### What is Data Masking
//
// Data masking is the process of turning sensitive data into fake, or masked,
// data that looks similar to the authentic data. Masking reveals no genuine
// information, making it useless to an attacker if intercepted.
//
// Data masking is challenging. The masked data set needs to maintain the
// complexity and unique characteristics of the original unmasked data set so
// queries and analysis still yield the same results. This means masked data
// must maintain referential integrity across systems and databases.
// An individual's Social Security number, for example, must get masked to the
// same SSN to preserve primary and foreign keys and relationships.
// It's important to note, however, that not every data field needs masking.
//
// ### Types of data masking
//
// A variety of data masking techniques can be used to obfuscate data depending
// on the type, including the following:
//
// - `Scrambling` randomly orders alphanumeric characters to obscure the
// original content.
// - `Substitution` replaces the original data with another value, while
// preserving the original characteristics of the data.
// - `Shuffling` rearranges values within a column, such as user surnames.
// - `Date aging` increases or decreases a date field by a specific date range.
// - `Variance` applies a variance to number or date fields. It is often used
// to mask financial and transaction information.
// - `Masking out` scrambles only part of a value. It is commonly applied to
// credit card numbers where only the last four digits remain unchanged.
// - `Nullifying` replaces the real values with a null value.
//
// The three main types of data masking are the following:
// - `Dynamic data masking` is applied in real time to provide role-based security;
// for example, returning masked data to a user who does not have the
// authority to see the real data.
// - `Static data` masking creates a separate masked set of the data that can
// be used for research and development.
// - `On-the-fly data masking` enables development teams to quickly read and
// mask a small subset of production data to use in a test environment.
package masking
