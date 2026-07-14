mod pcapng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcapng() {
        let mut p_handle = pcapng::pcapng::new();
        let res = p_handle.open("test.pcapng".to_string());
        println!("res {}", res);
    }
}
