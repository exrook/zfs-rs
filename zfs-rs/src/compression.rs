use nom::combinator::map_res;
use nom::multi::length_data;
use nom::number::complete::be_u32;
use nom::IResult;

pub fn decompress_lz4(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    map_res(length_data(be_u32), lz4_compression::decompress::decompress)(input)
}
