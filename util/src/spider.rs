use std::error::Error;
use std::f64::consts::{FRAC_PI_2, TAU};

use plotters::chart::ChartBuilder;
use plotters::coord::Shift;
use plotters::drawing::DrawingArea;
use plotters::element::{Circle, Polygon, Text};
use plotters::prelude::{Color, DrawingBackend};
use plotters::prelude::full_palette::GREY;
use plotters::series::LineSeries;
use plotters::style::full_palette::{GREY_800, LIGHTBLUE};
use plotters::style::text_anchor::{HPos, Pos, VPos};
use plotters::style::{RGBColor, TextStyle};

use scayl::DeploymentScore;

fn vertices(radius: f64, n: usize) -> Vec<(f64, f64)> {
    (0..n)
        .map(|v| {
            let angle = FRAC_PI_2 + TAU * v as f64 / n as f64;
            (radius * angle.cos(), radius * angle.sin())
        })
        .collect()
}

pub fn spider<DB: DrawingBackend>(root: &DrawingArea<DB, Shift>, score: &DeploymentScore) -> Result<(), Box<dyn Error>>
    where DB::ErrorType: 'static {
    let mut chart = ChartBuilder::on(root)
        .caption(format!("Deployment Score: {}", score.source), ("Roboto", 48))
        .margin(32)
        .build_cartesian_2d(-8.0f64..8.0, -8.0f64..8.0)?;

    chart
        .configure_mesh()
        .disable_x_mesh()
        .disable_y_mesh()
        .draw()?;

    for degree in 1usize..=6 {
        let mut vertices = vertices(degree as f64, 5);
        vertices.push(vertices[0]);
        let series = LineSeries::new(vertices, &GREY);
        chart.draw_series(series)?;
    }

    for deg in 0..5 {
        let theta = FRAC_PI_2 + TAU * deg as f64 / 5.0;
        let (x1, y1) = (theta.cos(), theta.sin());
        let (x2, y2) = (6.0 * theta.cos(), 6.0 * theta.sin());
        let series = LineSeries::new(vec![(x1, y1), (x2, y2)], &GREY);
        chart.draw_series(series)?;
    }

    let mut scores = [0.0; 5];
    const CATEGORIES: [&'static str; 5] = [
        "Network Configuration",
        "Remote Access",
        "File System Access",
        "Command Line Access",
        "Information Sensitivity",
    ];

    for (_, score) in &score.scores {
        scores[0] += score.network;
        scores[1] += score.remote;
        scores[2] += score.files;
        scores[3] += score.permissions;
        scores[4] += score.information;
    }

    let mut vertices = vec![];

    let style = TextStyle {
        font: ("Arial", 16).into(),
        color: GREY_800.to_backend_color(),
        pos: Pos::new(HPos::Center, VPos::Center),
    };

    const COLOR: &'static RGBColor = &LIGHTBLUE;

    for (i, score) in scores.iter()
        .map(|v| *v as f64)
        .map(|v| v / score.scores.len() as f64)
        .enumerate()
    {
        let theta = FRAC_PI_2 + TAU * i as f64 / 5.0;
        let (x, y) = (theta.cos(), theta.sin());
        let score = 1.0 + 5.0 * score;
        let point = (score * x, score * y);
        vertices.push(point);
        chart.draw_series(std::iter::once(Circle::new(point, 2, COLOR.filled())))?;

        let (x, y) = (6.75 * x, 6.75 * y);
        let text = Text::new(CATEGORIES[i], (x, y), style.clone());
        chart.draw_series(std::iter::once(text))?;
        let text = Text::new(
            format!("{:.2}", score),
            (x, y - 0.35),
            style.clone()
        );
        chart.draw_series(std::iter::once(text))?;
    }

    vertices.push(vertices[0]);
    chart.draw_series(LineSeries::new(vertices.clone(), COLOR))?;

    chart.draw_series(std::iter::once(Polygon::new(
        vertices,
        COLOR.mix(0.2),
    )))?;

    let style = TextStyle {
        font: ("Arial", 16).into(),
        color: GREY.to_backend_color(),
        pos: Pos::new(HPos::Left, VPos::Center),
    };

    for rad in 1..=6 {
        let (x, y) = (0.1, rad as f64);
        chart.draw_series(std::iter::once(Text::new(
            format!("{:.1}", (rad - 1) as f64 / 5.0),
            (x, y),
            style.clone(),
        )))?;
    }

    root.present()?;

    Ok(())
}