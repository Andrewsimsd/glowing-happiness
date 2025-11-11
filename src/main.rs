#![warn(clippy::pedantic)]
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests() {
        assert_eq!(0, 0);
    }
}
