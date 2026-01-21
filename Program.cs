using FraudDetection.Trainer.RandomDataSetGenerate.Models;
using FraudDetection.Trainer.RandomDataSetGenerate.Utility;
using System.Diagnostics;
using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

namespace FraudDetection.Trainer.RandomDataSetGenerate {
	public static class Program {
		/// <summary>
		/// Generates realistic synthetic login events and writes them to a CSV file in order to train Fraud Detection ML models. 
		/// This is eventually going into a class library. For now, the values are constant.
		/// </summary>
		public static async Task Main() {
			const int _daysAgo = 7;
			const int _eventsPerDay = 8000;

			ColorConsole.Teal(_programStartGenerating);

			// Generate login events
			List<LoginEvent> events = await StartGenerating(_daysAgo, _eventsPerDay);

			ColorConsole.Teal($"{_generatedText}{events.Count.ToString(_eventsGeneratedStringFormat)}");
			ColorConsole.Teal($"{_elapsed}{_sw.Elapsed.TotalSeconds}{Environment.NewLine}");

			// Write to CSV
			await StartWriting(events);

			ColorConsole.Orange(_finishText);
		}

		/// <summary>
		/// Generates a synthetic list of login events over a specified number of days, with a defined number of events per
		/// day and a reproducible random seed.
		/// </summary>
		/// <param name="days">The number of days in the past for which to generate login events. Must be greater than zero.</param>
		/// <param name="eventsPerDay">The number of login events to generate for each day. Must be greater than zero.</param>
		/// <param name="seed">The seed value used to initialize the random number generator, ensuring reproducible event generation.</param>
		/// <returns>A task that represents the asynchronous operation. The result contains a list of generated login events spanning
		/// the specified date range.</returns>
		private static async Task<List<LoginEvent>> StartGenerating(int days, int eventsPerDay) {
			DateTime utcEnd = DateTime.UtcNow;
			DateTime utcStart = utcEnd.AddDays(-1 * days);

			_sw.Start();
			SyntheticLoginGenerator generator = new();
			return generator.Generate(utcStart, utcEnd, eventsPerDay);
		}

		/// <summary>
		/// Writes the specified collection of login events to a CSV file asynchronously.
		/// </summary>
		/// <remarks>The output file path is determined by internal configuration. The method displays progress and
		/// file location information to the console during execution.</remarks>
		/// <param name="events">A list of <see cref="LoginEvent"/> objects representing the login events to write to the CSV file. Cannot be null.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		private static async Task StartWriting(List<LoginEvent> events) {
			_sw.Restart();
			string outputPath = $"{_loginEventsCsvPrefix}{_loginEventsCsvName}";

			ColorConsole.Teal($"{_generatedText}{events.Count.ToString(_eventsGeneratedStringFormat)}");
			ColorConsole.Teal($"{_elapsed}{_sw.Elapsed.TotalSeconds}{Environment.NewLine}");
			ColorConsole.Teal(_writingToCsv);

			ToCsv.Write(outputPath, events);

			ColorConsole.Green($"{_csvLocation}");
			ColorConsole.Pink($"{Path.GetFullPath(outputPath)}{Environment.NewLine}");

			_sw.Stop();
		}
		private static readonly Stopwatch _sw = new();
	}
}


